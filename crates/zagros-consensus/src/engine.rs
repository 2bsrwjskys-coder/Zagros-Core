//! Deterministik BFT konsensüs motoru (CONSENSUS-SPEC v0.2 §4–§8). SAF durum
//! makinesi: saat okumaz (`now_ms` girdidir), ağ/disk bilmez; aynı girdi sırası
//! ⇒ aynı çıktı sırası. Proposer `(h + r) mod N`, PREVOTE/PRECOMMIT, kilit,
//! Q = ⌊2N/3⌋+1 ile QC commit, timer'lar `T_base×(1+r)` (tavan 10×),
//! view-change, f+1 oyla tur atlama, INV-C4, heartbeat, zaman damgası kabulü (§7).
//! LİVENESS KARARI: oy timer'ları node kendi oyunu attığı anda kurulur (Q
//! beklenmez); tur ilerler, commit yine yalnız QC ile (INV-C3). Fail-closed:
//! doğrulanmayan mesaj `Output::Dropped`; timeout hiçbir koşulda QC'siz commit üretmez.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use zagros_crypto::{
    build_qc, sign_header, sign_heartbeat, sign_vote, verify_digest, verify_heartbeat, verify_qc,
    verify_signed_header, verify_vote, ConsensusKeypair,
};
use zagros_executor::bridge::BridgeProposal;
use zagros_primitives::{Hash, Result, ZagrosError};
use zagros_types::consensus::{
    block_body_bytes, byzantine_tolerance, signing_digest, ActiveValidatorSet, BlockHeaderV2,
    ChainParams, ConsensusDomain, Evidence, Heartbeat, QuorumCertificate, ShadowVoteAttestation,
    SignedHeader, Vote, VotePhase, DOMAIN_HEADER, NIL_HASH,
};
use zagros_types::Transaction;

/// Bir yükseklik için ileri-tamponlanacak azami mesaj (bellek tavanı; aşımı
/// düşürülür, sessiz büyüme yok).
const MAX_BUFFERED_PER_HEIGHT: usize = 4096;
/// Mevcut yüksekliğin en fazla kaç ilerisi tamponlanır.
const MAX_LOOKAHEAD_HEIGHTS: u64 = 2;
/// Mevcut turun en fazla kaç ilerisindeki öneri/oy kabul edilir.
const MAX_LOOKAHEAD_ROUNDS: u32 = 16;
/// §8: timer tavanı `10 × T_base`.
const TIMEOUT_CAP_MULTIPLIER: u64 = 10;
/// Öneri zarfı imza digest'inde phase baytı (header imzası phase=0 kullanır;
/// aynı DOMAIN_HEADER etiketi altında ayrışma için 1).
const ENVELOPE_PHASE: u8 = 1;

// MESAJLAR / ÇIKTILAR

/// Öneri zarfı (§8): `signed` asıl başlık (hash'i oy/QC kimliği), `round`
/// zarfın turu, `valid_round` POL turu, `sig` proposer imzası. Yeniden öneri
/// aynı başlığı taşır, kilit/QC kimliği turdan bağımsız (INV-C2/C4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub signed: SignedHeader,
    pub txs: Vec<Transaction>,
    pub bridge_proposals: Vec<BridgeProposal>,
    /// G8: proposer'ın topladığı `ShadowVoteAttestation`lar; header'da ayrı
    /// alan yok, doğrudan deterministik yürütmeye girer, her doğrulayıcı yeniden doğrular.
    #[serde(default)]
    pub shadow_votes: Vec<ShadowVoteAttestation>,
    pub round: u32,
    pub valid_round: Option<u32>,
    pub sig: Vec<u8>,
}

impl Proposal {
    pub fn block_hash(&self) -> Hash {
        self.signed.header.hash()
    }
    pub fn height(&self) -> u64 {
        self.signed.header.number
    }
    /// Zarf digest'i: `HEADER ‖ … ‖ height ‖ envelope_round ‖ phase=1 ‖ block_hash`.
    pub fn envelope_digest(&self, domain: &ConsensusDomain, epoch: u64) -> Hash {
        signing_digest(
            DOMAIN_HEADER,
            domain,
            epoch,
            self.height(),
            self.round,
            ENVELOPE_PHASE,
            &self.block_hash(),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    /// Kutulu: `Vote` ile boyut farkı büyük (clippy large_enum_variant).
    Proposal(Box<Proposal>),
    Vote(Vote),
    Heartbeat(Heartbeat),
    /// G8: Probation validator'ın gölge oyu. Motor state makinesinde işlemez
    /// (INV-L4); sürücü yakalayıp bloğa gömülecek havuza ekler, `handle()`a ulaşırsa düşürülür.
    ShadowVote(zagros_types::consensus::ShadowVoteAttestation),
}

impl Message {
    pub fn height(&self) -> u64 {
        match self {
            Message::Proposal(p) => p.height(),
            Message::Vote(v) => v.height,
            Message::Heartbeat(h) => h.height,
            Message::ShadowVote(sv) => sv.vote.height,
        }
    }
}

/// Kesinleşmiş blok: host bunu `Runtime::commit_block` ile uygular.
#[derive(Debug, Clone)]
pub struct CommittedBlock {
    pub proposal: Proposal,
    pub qc: QuorumCertificate,
    /// Bu yükseklikte kaç tur harcandı (liveness/progress muhasebesi).
    pub rounds_used: u32,
    /// ⏱️ QC nasıl kapandı (ölçüm/rapor; kural değil).
    pub qc_close: QcClose,
}

/// ⏱️ QC kapanış sebebi (bkz. `BftEngine::qc_grace_ms`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QcClose {
    /// Q'ya ulaşıldığı anda zaten N oyun tamamı vardı (ya da grace = 0).
    Immediate,
    /// Q'dan sonra beklerken N. oy geldi → grace dolmadan kapandı.
    Full,
    /// Grace doldu, eldeki (≥Q, <N) oyla kapandı.
    GraceExpired,
    /// Grace penceresi precommit deadline'ına sığmadığı için beklenmedi.
    Clamped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewChangeReason {
    /// Precommit timer'ı doldu (§8).
    Timeout,
    /// Q × PRECOMMIT(nil) (§8).
    NilQuorum,
    /// f+1 validator'dan daha yüksek tur oyu görüldü.
    RoundSkip,
}

#[derive(Debug, Clone)]
pub enum Output {
    /// Ağa yayınlanacak mesaj (kendi önerimiz/oyumuz; motor bunu kendi
    /// içinde de işlemiştir, host tekrar beslemez).
    Broadcast(Message),
    /// Bu node bu (height, round) için proposer ve öneri penceresi açık:
    /// host `propose()` (işlem varsa / boş blok vadesi dolduysa) ya da
    /// `heartbeat()` çağırmalı.
    NeedProposal { height: u64, round: u32 },
    /// QC tamamlandı; host commit etmeli (sırayla, atlamadan), sonra `start()`.
    Commit(Box<CommittedBlock>),
    /// Equivocation kanıtı (G7'de zincire yazılır; şimdilik yüzeye çıkarılır).
    Evidence(Evidence),
    /// Tur değişti (gözlemlenebilirlik: `view_change_rate` alarmı için).
    ViewChange {
        height: u64,
        from_round: u32,
        to_round: u32,
        reason: ViewChangeReason,
    },
    /// Geçersiz/alakasız mesaj düşürüldü (sebep; test/gözlemlenebilirlik).
    Dropped(String),
}

// HOST ARAYÜZÜ

/// Blok gövdesini gerçek state'e DOKUNMADAN yürütüp `state_root` döner
/// (`Runtime::simulate_block`). Hata = blok geçersiz (prevote nil).
pub trait BlockVerifier {
    fn simulate(
        &self,
        header: &BlockHeaderV2,
        txs: &[Transaction],
        bridge_proposals: &[BridgeProposal],
        shadow_votes: &[ShadowVoteAttestation],
    ) -> Result<Hash>;
}

/// `Runtime` üstünde `BlockVerifier`: header.timestamp_ms → saniye (mevcut
/// executor zaman birimi).
pub struct RuntimeVerifier(pub std::sync::Arc<zagros_runtime::Runtime>);

impl BlockVerifier for RuntimeVerifier {
    fn simulate(
        &self,
        header: &BlockHeaderV2,
        txs: &[Transaction],
        bridge_proposals: &[BridgeProposal],
        shadow_votes: &[ShadowVoteAttestation],
    ) -> Result<Hash> {
        // G7/G8/G9: `last_qc`, gölge oylar ve gerçek proposer simülasyona da
        // verilir; liveness ve üretici payı doğrulayıcının yeniden yürütmesiyle AYNI olmalı (INV-P2).
        self.0.simulate_block(
            header.number,
            (header.timestamp_ms / 1000) as u128,
            txs,
            bridge_proposals,
            header.last_qc.as_ref(),
            shadow_votes,
            Some((header.epoch, header.proposer_idx, header.max_ruleset)),
        )
    }
}

/// Bu node'un konsensüs kimliği. `None` = gözlemci (oy vermez, önermez; yine
/// de QC'leri doğrulayıp commit eder).
pub struct NodeIdentity {
    pub idx: u16,
    pub keypair: ConsensusKeypair,
}

/// Son kesinleşmiş blok. Genesis: `height = 0`, `hash = genesis block_0 hash`,
/// `qc = None` (yalnız genesis için izinli), `timestamp_ms` = genesis zamanı.
#[derive(Debug, Clone, PartialEq)]
pub struct ChainTip {
    pub height: u64,
    pub hash: Hash,
    pub qc: Option<QuorumCertificate>,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Propose,
    Prevote,
    Precommit,
}

/// Liveness/progress muhasebesi (yerel; zincire yazım G7).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EngineStats {
    pub view_changes_total: u64,
    pub timeouts_total: u64,
    pub nil_quorum_view_changes: u64,
    pub round_skips: u64,
    pub commits_total: u64,
    pub last_commit_round: u32,
}

// MOTOR

/// Restart güvenli çift imza koruması (`priv_validator_state` deseni): imzalanan
/// en yüksek (height, round, step) diske yazılır, sonraki imza yalnız kesin
/// büyükse atılır; aynı üçlüde aynı hash tekrar imzalanabilir, farklı hash
/// REDDEDİLİR. Kayıt atomik (tmp + fsync + rename + dizin fsync), her kolda
/// FAIL-CLOSED: yazılamazsa ya da dosya var ama bozuksa imzalanmaz; dosya yoksa temiz başlangıç.
pub struct DoubleSignProtector {
    path: std::path::PathBuf,
    highest: Option<(u64, u32, u8, Hash)>,
    /// Dosya var ama okunamadı: watermark bilinmiyor, `allow` hep `false`.
    /// Kurtarma: "<güncel_yükseklik+1> 0 0 <64 sıfır>" yazılabilir.
    poisoned: bool,
}

impl DoubleSignProtector {
    pub fn load(path: &std::path::Path) -> Self {
        match std::fs::read_to_string(path) {
            // Dosya YOK: ilk açılış / hiç imza atılmamış → temiz başlangıç meşru.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self {
                path: path.to_path_buf(),
                highest: None,
                poisoned: false,
            },
            // Dosya var ama OKUNAMIYOR (izin/IO): watermark bilinmiyor → fail-closed.
            Err(e) => {
                tracing::error!(
                    "🛑 çift-imza durum dosyası okunamadı ({}): {e} - İMZALAMA ENGELLENDİ; \
                     dosyayı inceleyin (kurtarma: struct doc'undaki güvenli değer)",
                    path.display()
                );
                Self {
                    path: path.to_path_buf(),
                    highest: None,
                    poisoned: true,
                }
            }
            Ok(s) => match Self::parse(&s) {
                Some(v) => Self {
                    path: path.to_path_buf(),
                    highest: Some(v),
                    poisoned: false,
                },
                // Dosya var ama BOZUK (yarım yazım/çöp): sessizce temiz başlangıç
                // saymak tam da korumanın kapandığı an → fail-closed.
                None => {
                    tracing::error!(
                        "🛑 çift-imza durum dosyası BOZUK ({}) - İMZALAMA ENGELLENDİ; \
                         dosyayı inceleyin (kurtarma: struct doc'undaki güvenli değer)",
                        path.display()
                    );
                    Self {
                        path: path.to_path_buf(),
                        highest: None,
                        poisoned: true,
                    }
                }
            },
        }
    }

    fn parse(s: &str) -> Option<(u64, u32, u8, Hash)> {
        let mut it = s.split_whitespace();
        let h: u64 = it.next()?.parse().ok()?;
        let r: u32 = it.next()?.parse().ok()?;
        let step: u8 = it.next()?.parse().ok()?;
        let bytes = hex::decode(it.next()?).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        Some((h, r, step, hash))
    }

    /// `true` = imzalamaya İZİN VAR (yeni watermark diske yazıldı). `false` =
    /// REDDET (çift-imza riski ya da kalıcılık başarısız). (h,r,step) üçlüleri
    /// leksikografik karşılaştırılır.
    pub fn allow(&mut self, height: u64, round: u32, step: u8, hash: Hash) -> bool {
        if self.poisoned {
            tracing::error!(
                "🛑 çift-imza durum dosyası bozuk/okunamaz olduğu için imza REDDEDİLDİ \
                 (h={height} r={round} step={step}); operatör müdahalesi gerekiyor: {}",
                self.path.display()
            );
            return false;
        }
        let cur = (height, round, step);
        match self.highest {
            Some((ph, pr, ps, phash)) => {
                let prev = (ph, pr, ps);
                if cur == prev {
                    // Aynı (h,r,step): aynı blok → deterministik imza (güvenli,
                    // yeniden yazmaya gerek yok); farklı blok → equivocation, RED.
                    return hash == phash;
                }
                if cur < prev {
                    return false; // geçmiş bir (h,r,step)'e imza YOK
                }
            }
            None => {}
        }
        // Yeni ve daha yüksek watermark: ÖNCE diske yaz, sonra izin ver.
        if self.persist(height, round, step, hash) {
            self.highest = Some((height, round, step, hash));
            true
        } else {
            false
        }
    }

    fn persist(&self, height: u64, round: u32, step: u8, hash: Hash) -> bool {
        // 🛡️ Yaz+rename yetmez: fsync'siz rename'de elektrik kesintisi dosyayı sıfır
        // uzunlukta bırakabilir. Sıra: tmp'ye yaz → dosyayı fsync → rename → dizini fsync.
        let line = format!("{} {} {} {}\n", height, round, step, hex::encode(hash));
        let tmp = self.path.with_extension("tmp");
        let write_res = (|| -> std::io::Result<()> {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(line.as_bytes())?;
            f.sync_all()?;
            drop(f);
            std::fs::rename(&tmp, &self.path)?;
            if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
                // Dizin fsync'i kimi dosya sistemlerinde desteklenmez; veri
                // zaten fsync'li olduğundan bu adımın hatası ölümcül sayılmaz.
                if let Ok(d) = std::fs::File::open(dir) {
                    let _ = d.sync_all();
                }
            }
            Ok(())
        })();
        match write_res {
            Ok(()) => true,
            Err(e) => {
                tracing::error!(
                    "🛑 çift-imza durum dosyası yazılamadı ({}): {e} - imzalama fail-closed engellendi",
                    self.path.display()
                );
                false
            }
        }
    }
}

pub struct BftEngine {
    /// §23 (G10): bu node'un başlıklarda beyan edeceği en yüksek kural seti.
    /// Üretimde `SUPPORTED_RULESET`; bft_sim karışık-sürüm testleri için
    /// `set_local_max_ruleset` ile değiştirilebilir.
    local_max_ruleset: u32,
    domain: ConsensusDomain,
    params: ChainParams,
    identity: Option<NodeIdentity>,
    /// Mevcut yükseklikte geçerli küme `V_e`.
    set: ActiveValidatorSet,
    /// `tip`'in kesinleştiği yükseklikte geçerli olan küme (`last_qc` bu
    /// kümeye karşı doğrulanır; epoch sınırında `set`'ten farklı olabilir).
    tip_set: ActiveValidatorSet,
    tip: ChainTip,
    /// Yerel commit anı (idle sınırı için; konsensüs değeri değil).
    tip_committed_at_ms: u64,

    height: u64,
    round: u32,
    step: Step,
    /// `start()` ile tur 0 başlatıldı mı (commit sonrası host `start` çağırana
    /// kadar timer yok, mesajlar tamponlanır).
    round_active: bool,
    /// Kilit kuralı (§7): (round, hash).
    locked: Option<(u32, Hash)>,
    /// Bilinen son geçerli değer (POL'lü): (round, hash) + gövdesi.
    valid: Option<(u32, Hash)>,
    valid_proposal: Option<Proposal>,
    /// round → zarf (bu yükseklik). Aynı turda ikinci farklı hash = DoublePropose.
    proposals: HashMap<u32, Proposal>,
    /// Simülasyonu doğrulanmış header hash'leri (bu yükseklik).
    verified: HashMap<Hash, bool>,
    prevotes: HashMap<u32, HashMap<u16, Vote>>,
    precommits: HashMap<u32, HashMap<u16, Vote>>,
    /// Gövdesi henüz gelmemiş bir blok için toplanan QC.
    pending_qc: Option<QuorumCertificate>,
    /// İleri yükseklik (ve start() öncesi) mesajları (sınırlı).
    buffered: BTreeMap<u64, Vec<Message>>,
    /// Bu yükseklikte zaten yayınlanan kanıtlar (tekrar etmemek için).
    evidence_seen: Vec<(u16, u32, u8)>,

    /// ⏱️ QC kapanış toleransı (ms). 0 = eski davranış (Q görülünce hemen kapat).
    /// Sürücü state'ten (`__QC_GRACE_MS__`, yoksa 200) her commit'te tazeler.
    qc_grace_ms: u64,
    /// Bekleyen grace penceresi: (tur, hash, son an). Q×PRECOMMIT(hash) görüldü
    /// ama N oy tamam değil; `next_deadline()` bunu da sayar.
    qc_grace_wait: Option<(u32, Hash, u64)>,
    /// Son QC'nin kapanış sebebi (commit'te `CommittedBlock`'a yazılır).
    last_qc_close: QcClose,

    // ---- G4 timer'ları (mutlak ms; host `next_deadline()` ile öğrenir) ----
    propose_ready_at: Option<u64>,
    propose_deadline: Option<u64>,
    prevote_deadline: Option<u64>,
    precommit_deadline: Option<u64>,
    stats: EngineStats,
    /// Çift imza koruması; `None` = kapalı (test/yerel). Motor her commit'te
    /// yeniden kurulduğundan koruma dosyadan yüklenir, restart'lar arası sürer.
    double_sign: Option<DoubleSignProtector>,
}

impl BftEngine {
    /// `tip_set`: `tip.qc`nin doğrulanacağı küme, tip'in kesinleştiği epoch'un
    /// kümesi (güncel `set`ten farklı olabilir; karıştırmak yanlış `Err` üretir).
    /// `None` = `set` ile aynı (genesis ya da epoch ilerlememişse doğru).
    pub fn new(
        domain: ConsensusDomain,
        params: ChainParams,
        set: ActiveValidatorSet,
        identity: Option<NodeIdentity>,
        tip: ChainTip,
        tip_set: Option<ActiveValidatorSet>,
    ) -> Result<Self> {
        params.validate()?;
        set.validate()?;
        let tip_set = match tip_set {
            Some(ts) => {
                ts.validate()?;
                ts
            }
            None => set.clone(),
        };
        if let Some(id) = &identity {
            match set.pubkey_of(id.idx) {
                Some(pk) if *pk == id.keypair.public_key() => {}
                _ => {
                    return Err(ZagrosError::Other(
                        "konsensus kimligi: idx/pubkey aktif kumeyle uyusmuyor".into(),
                    ))
                }
            }
        }
        if tip.height > 0 {
            match &tip.qc {
                Some(qc) => {
                    if qc.height != tip.height || qc.block_hash != tip.hash {
                        return Err(ZagrosError::Other("tip.qc tip ile uyusmuyor".into()));
                    }
                    verify_qc(qc, &domain, &tip_set)?;
                }
                None => return Err(ZagrosError::Other("genesis disinda tip QC tasimali".into())),
            }
        }
        Ok(Self {
            local_max_ruleset: zagros_types::consensus::SUPPORTED_RULESET,
            domain,
            params,
            identity,
            tip_set,
            set,
            height: tip.height + 1,
            tip,
            tip_committed_at_ms: 0,
            round: 0,
            step: Step::Propose,
            round_active: false,
            locked: None,
            valid: None,
            valid_proposal: None,
            proposals: HashMap::new(),
            verified: HashMap::new(),
            prevotes: HashMap::new(),
            precommits: HashMap::new(),
            pending_qc: None,
            buffered: BTreeMap::new(),
            evidence_seen: Vec::new(),
            qc_grace_ms: 0,
            qc_grace_wait: None,
            last_qc_close: QcClose::Immediate,
            propose_ready_at: None,
            propose_deadline: None,
            prevote_deadline: None,
            precommit_deadline: None,
            stats: EngineStats::default(),
            double_sign: None,
        })
    }

    /// Çift-imza korumasını dosya yoluyla etkinleştirir (sürücü, config'ten
    /// geçirir). Dosyadan mevcut en yüksek imzalanan (h,r,step) yüklenir; böylece
    /// motor yeniden kurulsa/node restart olsa da watermark korunur.
    pub fn set_double_sign_protector(&mut self, path: &std::path::Path) {
        self.double_sign = Some(DoubleSignProtector::load(path));
    }

    // ---- gözlem ----
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn round(&self) -> u32 {
        self.round
    }
    pub fn step(&self) -> Step {
        self.step
    }
    pub fn tip(&self) -> &ChainTip {
        &self.tip
    }
    pub fn locked(&self) -> Option<(u32, Hash)> {
        self.locked
    }
    pub fn valid(&self) -> Option<(u32, Hash)> {
        self.valid
    }
    pub fn validator_set(&self) -> &ActiveValidatorSet {
        &self.set
    }
    pub fn my_idx(&self) -> Option<u16> {
        self.identity.as_ref().map(|i| i.idx)
    }
    pub fn stats(&self) -> EngineStats {
        self.stats
    }
    /// G6: gövdesi henüz gelmemiş ama QC'si tamamlanmış blok (catch-up tetiği).
    pub fn pending_qc_hash(&self) -> Option<Hash> {
        self.pending_qc.as_ref().map(|q| q.block_hash)
    }
    /// Host'un `tick()` çağırması gereken en erken an (ms). `None` = timer yok.
    pub fn next_deadline(&self) -> Option<u64> {
        [
            self.propose_ready_at,
            self.propose_deadline,
            self.prevote_deadline,
            self.precommit_deadline,
            self.qc_grace_wait.map(|(_, _, at)| at),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// ⏱️ QC kapanış toleransını ayarlar (ms). Değer, sürücü tarafından
    /// `validate_qc_grace` ile zaten sınırlanmış olmalı; motor yine de
    /// precommit deadline'ını asla geçmez (`qc_grace_deadline`).
    pub fn set_qc_grace_ms(&mut self, ms: u64) {
        self.qc_grace_ms = ms;
    }
    pub fn qc_grace_ms(&self) -> u64 {
        self.qc_grace_ms
    }
    /// Test/izleme: bekleyen grace penceresi var mı.
    pub fn qc_grace_waiting(&self) -> bool {
        self.qc_grace_wait.is_some()
    }

    /// Grace penceresinin son anı: `since + grace`, ama precommit deadline'ından
    /// en az 1 ms önce (INV: grace hiçbir koşulda tur bütçesini aşamaz → view
    /// change zincirlenemez). Sığmıyorsa `None` = bekleme, hemen kapat.
    fn qc_grace_deadline(&self, since: u64) -> Option<u64> {
        if self.qc_grace_ms == 0 {
            return None;
        }
        let at = since.saturating_add(self.qc_grace_ms);
        match self.precommit_deadline {
            Some(pd) if at.saturating_add(1) >= pd => None,
            _ => Some(at),
        }
    }

    /// Rotasyon (§4): `proposer(h, r) = (h + r) mod N`.
    pub fn proposer_for(&self, height: u64, round: u32) -> u16 {
        let n = self.set.len() as u64;
        ((height + round as u64) % n) as u16
    }
    pub fn is_proposer(&self) -> bool {
        self.my_idx() == Some(self.proposer_for(self.height, self.round))
    }

    /// §8: `T_propose(r) = T_base × (1+r)`, tavan `10 × T_base`.
    pub fn t_propose(&self, round: u32) -> u64 {
        let t = self.params.t_base_ms.saturating_mul(1 + round as u64);
        t.min(self.params.t_base_ms.saturating_mul(TIMEOUT_CAP_MULTIPLIER))
    }
    /// §8: `T_vote(r) = T_base/2 × (1+r)`, aynı tavan.
    pub fn t_vote(&self, round: u32) -> u64 {
        let t = (self.params.t_base_ms / 2)
            .max(1)
            .saturating_mul(1 + round as u64);
        t.min(self.params.t_base_ms.saturating_mul(TIMEOUT_CAP_MULTIPLIER))
    }

    /// Epoch sınırı (§3): host, commit'ten SONRA ve `start()`'tan önce yeni
    /// kümeyi kurar. Kimlik yeni kümede yoksa gözlemciye düşer (fail-closed).
    pub fn rotate_validator_set(&mut self, new_set: ActiveValidatorSet) -> Result<()> {
        new_set.validate()?;
        if self.round_active || !self.proposals.is_empty() || !self.prevotes.is_empty() {
            return Err(ZagrosError::Other(
                "validator kumesi yalnizca yukseklik basinda (bos durumda) degistirilebilir".into(),
            ));
        }
        if let Some(id) = &self.identity {
            let still_member = new_set
                .members
                .iter()
                .position(|m| m.consensus_pubkey == id.keypair.public_key());
            match still_member {
                Some(i) => {
                    let kp = ConsensusKeypair::from_secret_bytes(&id.keypair.secret_bytes());
                    self.identity = Some(NodeIdentity {
                        idx: i as u16,
                        keypair: kp,
                    });
                }
                None => self.identity = None,
            }
        }
        self.set = new_set;
        Ok(())
    }

    /// Yüksekliği başlatır/sürdürür. Host bunu (a) motor kurulunca, (b) HER
    /// `Output::Commit`'i `Runtime::commit_block` ile uyguladıktan SONRA çağırır.
    /// Tur 0 ve timer'lar burada başlar; tamponlanmış mesajlar commit edilmiş
    /// state üzerinde oynatılır.
    pub fn start(&mut self, now_ms: u64, verifier: &dyn BlockVerifier) -> Vec<Output> {
        let mut out = Vec::new();
        if self.tip_committed_at_ms == 0 {
            // Genesis / yeniden başlatma: idle penceresi motorun başladığı anda açılır.
            self.tip_committed_at_ms = now_ms;
        }
        if !self.round_active {
            self.round_active = true;
            out.extend(self.start_round(0, now_ms, None, verifier));
        }
        let replay: Vec<Message> = self.buffered.remove(&self.height).unwrap_or_default();
        self.buffered.retain(|h, _| *h > self.height);
        for msg in replay {
            out.extend(self.handle(msg, now_ms, verifier));
        }
        out
    }

    /// Timer kontrolü. Host `next_deadline()` zamanında (veya herhangi bir
    /// zamanda) çağırır; idempotent.
    pub fn tick(&mut self, now_ms: u64, verifier: &dyn BlockVerifier) -> Vec<Output> {
        let mut out = Vec::new();
        if !self.round_active {
            return out;
        }
        if let Some(at) = self.propose_ready_at {
            if now_ms >= at {
                self.propose_ready_at = None;
                if self.is_proposer()
                    && self.step == Step::Propose
                    && !self.proposals.contains_key(&self.round)
                {
                    out.push(Output::NeedProposal {
                        height: self.height,
                        round: self.round,
                    });
                }
            }
        }
        if let Some(at) = self.propose_deadline {
            if now_ms >= at {
                self.propose_deadline = None;
                self.propose_ready_at = None;
                if self.step == Step::Propose {
                    // FM-C1: lider sessiz → PREVOTE(nil)
                    self.stats.timeouts_total += 1;
                    self.step = Step::Prevote;
                    out.extend(self.cast_vote(VotePhase::Prevote, NIL_HASH, now_ms, verifier));
                }
            }
        }
        if let Some(at) = self.prevote_deadline {
            if now_ms >= at {
                self.prevote_deadline = None;
                if self.step == Step::Prevote {
                    self.stats.timeouts_total += 1;
                    self.step = Step::Precommit;
                    out.extend(self.cast_vote(VotePhase::Precommit, NIL_HASH, now_ms, verifier));
                }
            }
        }
        if let Some(at) = self.precommit_deadline {
            if now_ms >= at {
                self.precommit_deadline = None;
                // 🛡️ `qc_grace_wait` açıksa Q precommit toplanmış, yalnız kapanış
                // bekleniyor; gecikmiş uyanışta gereksiz view-change üretmemek
                // için timeout bastırılır, `try_advance` pencereyi kapatır.
                if self.step == Step::Precommit
                    && self.pending_qc.is_none()
                    && self.qc_grace_wait.is_none()
                {
                    self.stats.timeouts_total += 1;
                    let next = self.round + 1;
                    out.extend(self.start_round(
                        next,
                        now_ms,
                        Some(ViewChangeReason::Timeout),
                        verifier,
                    ));
                    return out;
                }
            }
        }
        out.extend(self.try_advance(now_ms, verifier));
        out
    }

    fn start_round(
        &mut self,
        round: u32,
        now_ms: u64,
        reason: Option<ViewChangeReason>,
        verifier: &dyn BlockVerifier,
    ) -> Vec<Output> {
        let mut out = Vec::new();
        if let Some(reason) = reason {
            // INV-T1: tur monoton.
            debug_assert!(round > self.round);
            out.push(Output::ViewChange {
                height: self.height,
                from_round: self.round,
                to_round: round,
                reason,
            });
            self.stats.view_changes_total += 1;
            match reason {
                ViewChangeReason::NilQuorum => self.stats.nil_quorum_view_changes += 1,
                ViewChangeReason::RoundSkip => self.stats.round_skips += 1,
                ViewChangeReason::Timeout => {}
            }
        }
        self.round = round;
        self.step = Step::Propose;
        self.prevote_deadline = None;
        self.precommit_deadline = None;
        self.qc_grace_wait = None;
        // §8: timer başlangıcı öneri penceresi = max(commit, parent.ts + block_interval).
        let window_start = now_ms.max(
            self.tip
                .timestamp_ms
                .saturating_add(self.params.block_interval_ms),
        );
        self.propose_deadline = Some(window_start.saturating_add(self.t_propose(round)));
        self.propose_ready_at = None;
        if self.is_proposer() && !self.proposals.contains_key(&round) {
            if now_ms >= window_start {
                out.push(Output::NeedProposal {
                    height: self.height,
                    round,
                });
            } else {
                self.propose_ready_at = Some(window_start);
            }
        }
        // Bu tur için daha önce gelmiş (tamponlanmış) öneri varsa şimdi işle.
        if let Some(p) = self.proposals.remove(&round) {
            out.extend(self.on_proposal(p, now_ms, verifier));
        }
        out.extend(self.try_advance(now_ms, verifier));
        out
    }

    // ---- öneri / heartbeat ----

    /// Host, `NeedProposal`'a cevaben çağırır. `valid` değer varsa (§7/INV-C4)
    /// verilen gövde YOK SAYILIR ve o değer AYNI başlıkla yeniden önerilir
    /// (`valid_round` = POL turu).
    pub fn propose(
        &mut self,
        now_ms: u64,
        txs: Vec<Transaction>,
        bridge_proposals: Vec<BridgeProposal>,
        shadow_votes: Vec<ShadowVoteAttestation>,
        verifier: &dyn BlockVerifier,
    ) -> Result<Vec<Output>> {
        let Some(id) = &self.identity else {
            return Err(ZagrosError::Other("gozlemci oneri yapamaz".into()));
        };
        if !self.round_active || !self.is_proposer() || self.step != Step::Propose {
            return Err(ZagrosError::Other(format!(
                "bu node h={} r={} icin su an oneremez (proposer degil / adim gecti)",
                self.height, self.round
            )));
        }
        if self.proposals.contains_key(&self.round) {
            return Err(ZagrosError::Other(
                "bu round icin zaten oneri var (double-propose engellendi)".into(),
            ));
        }

        let proposal = if let (Some((vr, _)), Some(vp)) = (self.valid, self.valid_proposal.as_ref())
        {
            let mut p = vp.clone();
            p.round = self.round;
            p.valid_round = Some(vr);
            if let Some(ds) = self.double_sign.as_mut() {
                if !ds.allow(self.height, self.round, 0u8, p.block_hash()) {
                    return Err(ZagrosError::Other(
                        "anti-equivocation: bu (h,r) icin propose reddedildi (restart guvenligi)"
                            .into(),
                    ));
                }
            }
            p.sig = id
                .keypair
                .sign_digest(&p.envelope_digest(&self.domain, self.set.epoch));
            p
        } else {
            let body_bytes = block_body_bytes(&txs);
            if body_bytes > self.params.max_block_bytes {
                return Err(ZagrosError::Other(format!(
                    "oneri govdesi {} > max_block_bytes {}",
                    body_bytes, self.params.max_block_bytes
                )));
            }
            if txs.len() > u32::MAX as usize {
                return Err(ZagrosError::Other("tx sayisi u32 sinirini asiyor".into()));
            }
            let timestamp_ms = now_ms.max(self.tip.timestamp_ms.saturating_add(1));
            let tx_hashes: Vec<Hash> = txs.iter().map(|t| t.tx_id).collect();
            let mut header = BlockHeaderV2 {
                version: BlockHeaderV2::VERSION,
                number: self.height,
                parent_hash: self.tip.hash,
                state_root: NIL_HASH,
                timestamp_ms,
                tx_root: BlockHeaderV2::compute_tx_root(&tx_hashes),
                tx_count: txs.len() as u32,
                body_bytes: body_bytes as u32,
                epoch: self.set.epoch,
                validator_set_hash: self.set.hash(),
                round: self.round,
                proposer_idx: id.idx,
                max_ruleset: self.local_max_ruleset,
                last_qc: self.tip.qc.clone(),
            };
            header.state_root =
                verifier.simulate(&header, &txs, &bridge_proposals, &shadow_votes)?;
            header.validate_structure(&self.params)?;
            if let Some(ds) = self.double_sign.as_mut() {
                if !ds.allow(self.height, self.round, 0u8, header.hash()) {
                    return Err(ZagrosError::Other(
                        "anti-equivocation: bu (h,r) icin propose reddedildi (restart guvenligi)"
                            .into(),
                    ));
                }
            }
            let signed = sign_header(&id.keypair, &self.domain, header);
            let mut p = Proposal {
                signed,
                txs,
                bridge_proposals,
                shadow_votes,
                round: self.round,
                valid_round: None,
                sig: Vec::new(),
            };
            p.sig = id
                .keypair
                .sign_digest(&p.envelope_digest(&self.domain, self.set.epoch));
            // Kendi simülasyonumuz = doğrulama; tekrar simüle etmeye gerek yok.
            self.verified.insert(p.block_hash(), true);
            p
        };

        let mut out = vec![Output::Broadcast(Message::Proposal(Box::new(
            proposal.clone(),
        )))];
        out.extend(self.on_proposal(proposal, now_ms, verifier));
        Ok(out)
    }

    /// §23 test kancası: yalnız bft_sim karışık-sürüm senaryoları için.
    pub fn set_local_max_ruleset(&mut self, v: u32) {
        self.local_max_ruleset = v;
    }

    /// Boşta lider: öneri yerine heartbeat yayınlar (§7/§8). Validator'lar
    /// öneri timer'ını sıfırlar, `idle_block_interval_s` dolana kadar.
    pub fn heartbeat(&mut self, now_ms: u64) -> Result<Vec<Output>> {
        let Some(id) = &self.identity else {
            return Err(ZagrosError::Other("gozlemci heartbeat gonderemez".into()));
        };
        if !self.round_active || !self.is_proposer() || self.step != Step::Propose {
            return Err(ZagrosError::Other(
                "heartbeat yalniz Propose adimindaki lider tarafindan gonderilir".into(),
            ));
        }
        let mut hb = Heartbeat {
            height: self.height,
            round: self.round,
            timestamp_ms: now_ms,
            validator_idx: id.idx,
            sig: Vec::new(),
        };
        sign_heartbeat(&id.keypair, &self.domain, self.set.epoch, &mut hb);
        // Kendi timer'ımızı da aynı kuralla sıfırla.
        let mut out = vec![Output::Broadcast(Message::Heartbeat(hb.clone()))];
        out.extend(self.on_heartbeat(hb, now_ms));
        Ok(out)
    }

    // ---- mesaj girişi ----

    pub fn handle(
        &mut self,
        msg: Message,
        now_ms: u64,
        verifier: &dyn BlockVerifier,
    ) -> Vec<Output> {
        let msg_height = msg.height();
        if msg_height < self.height {
            return vec![Output::Dropped(format!(
                "gecmis yukseklik {} < {}",
                msg_height, self.height
            ))];
        }
        if msg_height > self.height || !self.round_active {
            // İleri yükseklik ya da commit uygulanırken (host henüz start()
            // demedi) gelen mesaj: state hazır olunca oynatılır.
            return vec![self.buffer(msg_height, msg)];
        }
        match msg {
            Message::Proposal(p) => self.on_proposal(*p, now_ms, verifier),
            Message::Vote(v) => self.on_vote(v, now_ms, verifier),
            Message::Heartbeat(h) => self.on_heartbeat(h, now_ms),
            Message::ShadowVote(_) => vec![Output::Dropped(
                "shadow oy motor tarafindan islenmez (surucu katmaninda)".into(),
            )],
        }
    }

    fn buffer(&mut self, height: u64, msg: Message) -> Output {
        if height > self.height + MAX_LOOKAHEAD_HEIGHTS {
            return Output::Dropped(format!(
                "cok ileri yukseklik {} (simdi {})",
                height, self.height
            ));
        }
        let q = self.buffered.entry(height).or_default();
        if q.len() >= MAX_BUFFERED_PER_HEIGHT {
            return Output::Dropped(format!("yukseklik {} tamponu dolu", height));
        }
        q.push(msg);
        Output::Dropped(format!("yukseklik {} icin tamponlandi", height))
    }

    fn on_heartbeat(&mut self, hb: Heartbeat, now_ms: u64) -> Vec<Output> {
        if hb.round != self.round {
            return vec![Output::Dropped(format!(
                "heartbeat round {} != {}",
                hb.round, self.round
            ))];
        }
        if hb.validator_idx != self.proposer_for(self.height, self.round) {
            return vec![Output::Dropped(
                "heartbeat lider olmayan validator'dan".into(),
            )];
        }
        if let Err(e) = verify_heartbeat(&hb, &self.domain, &self.set) {
            return vec![Output::Dropped(format!("heartbeat imzasi: {e}"))];
        }
        if hb.timestamp_ms > now_ms.saturating_add(self.params.max_clock_skew_ms) {
            return vec![Output::Dropped("heartbeat zaman damgasi gelecekte".into())];
        }
        if self.step != Step::Propose {
            return vec![Output::Dropped("heartbeat: oneri adimi gecti".into())];
        }
        // İdle sınırı: lider sonsuza kadar heartbeat ile blok üretimini erteleyemez.
        let idle_limit = self
            .tip_committed_at_ms
            .saturating_add(self.params.idle_block_interval_s.saturating_mul(1000));
        if now_ms >= idle_limit {
            return vec![Output::Dropped(
                "heartbeat: bos blok vadesi doldu, timer sifirlanmadi".into(),
            )];
        }
        self.propose_deadline = Some(now_ms.saturating_add(self.t_propose(self.round)));
        Vec::new()
    }

    fn on_proposal(
        &mut self,
        p: Proposal,
        now_ms: u64,
        verifier: &dyn BlockVerifier,
    ) -> Vec<Output> {
        let mut out = Vec::new();
        let block_hash = p.block_hash();

        // Zarf imzası: proposer(h, zarf turu).
        let expected = self.proposer_for(self.height, p.round);
        match self.set.pubkey_of(expected) {
            Some(pk) => {
                if let Err(e) =
                    verify_digest(pk, &p.envelope_digest(&self.domain, self.set.epoch), &p.sig)
                {
                    return vec![Output::Dropped(format!(
                        "oneri zarf imzasi (round {}): {e}",
                        p.round
                    ))];
                }
            }
            None => {
                return vec![Output::Dropped(
                    "oneri: proposer indeksi kume disinda".into(),
                )]
            }
        }

        if p.round > self.round {
            if p.round > self.round + MAX_LOOKAHEAD_ROUNDS {
                return vec![Output::Dropped(format!(
                    "oneri cok ileri round {} (simdi {})",
                    p.round, self.round
                ))];
            }
            // Tur tamponu: ilk gelen saklanır; aynı turda farklı hash = kanıt.
            if let Some(existing) = self.proposals.get(&p.round) {
                if existing.block_hash() != block_hash {
                    out.extend(self.double_propose_evidence(existing.clone(), p));
                }
                out.push(Output::Dropped("ileri round icin oneri zaten var".into()));
                return out;
            }
            self.proposals.insert(p.round, p);
            out.push(Output::Dropped("ileri round icin tamponlandi".into()));
            return out;
        }

        if p.round < self.round {
            // Eski tur: yalnız bekleyen QC'nin gövdesi olarak kabul edilir.
            let wanted = self.pending_qc.as_ref().map(|qc| qc.block_hash) == Some(block_hash);
            if !wanted {
                return vec![Output::Dropped(format!(
                    "eski round {} onerisi (simdi {})",
                    p.round, self.round
                ))];
            }
            if let Err(e) = self.check_proposal(&p, now_ms, verifier) {
                return vec![Output::Dropped(format!(
                    "bekleyen QC govdesi gecersiz: {e}"
                ))];
            }
            self.verified.insert(block_hash, true);
            self.proposals.entry(p.round).or_insert(p);
            out.extend(self.try_advance(now_ms, verifier));
            return out;
        }

        // p.round == self.round
        if let Some(existing) = self.proposals.get(&p.round) {
            if existing.block_hash() == block_hash {
                return vec![Output::Dropped("oneri zaten alindi".into())];
            }
            out.extend(self.double_propose_evidence(existing.clone(), p));
            out.push(Output::Dropped(
                "ayni round'da ikinci oneri (equivocation)".into(),
            ));
            return out;
        }

        let valid = match self.check_proposal(&p, now_ms, verifier) {
            Ok(()) => true,
            Err(e) => {
                out.push(Output::Dropped(format!("oneri gecersiz: {e}")));
                false
            }
        };
        let valid_round = p.valid_round;
        if valid {
            self.verified.insert(block_hash, true);
            self.proposals.insert(p.round, p);
        }

        if self.step == Step::Propose {
            let vote_for = if !valid {
                NIL_HASH
            } else {
                match self.locked {
                    None => block_hash,
                    Some((_, locked_hash)) if locked_hash == block_hash => block_hash,
                    // INV-C4: kilitliyken başka değere yalnız daha yeni POL ile.
                    Some((locked_round, _)) => match valid_round {
                        Some(vr)
                            if vr > locked_round
                                && vr < self.round
                                && self.has_quorum_prevotes(vr, block_hash) =>
                        {
                            block_hash
                        }
                        _ => NIL_HASH,
                    },
                }
            };
            self.step = Step::Prevote;
            out.extend(self.cast_vote(VotePhase::Prevote, vote_for, now_ms, verifier));
        }
        out.extend(self.try_advance(now_ms, verifier));
        out
    }

    fn double_propose_evidence(&mut self, a: Proposal, b: Proposal) -> Vec<Output> {
        // Kanıt yapısı aynı (height, round, proposer) başlık çifti ister;
        // yeniden önerilerde (header.round ≠ zarf turu) başlıklar farklı turda
        // olabilir, o durumda yapısal kanıt üretilemez, yalnızca düşürülür.
        let (ha, hb) = (&a.signed.header, &b.signed.header);
        if ha.round != hb.round || ha.proposer_idx != hb.proposer_idx {
            return Vec::new();
        }
        let key = (ha.proposer_idx, ha.round, 0xFF);
        if self.evidence_seen.contains(&key) {
            return Vec::new();
        }
        self.evidence_seen.push(key);
        vec![Output::Evidence(Evidence::DoublePropose {
            a: Box::new(a.signed),
            b: Box::new(b.signed),
        })]
    }

    fn check_proposal(
        &self,
        p: &Proposal,
        now_ms: u64,
        verifier: &dyn BlockVerifier,
    ) -> Result<()> {
        let h = &p.signed.header;
        h.validate_structure(&self.params)?;
        if h.number != self.height {
            return Err(ZagrosError::Other("yukseklik uyusmuyor".into()));
        }
        if h.round > p.round {
            return Err(ZagrosError::Other("baslik turu zarf turundan buyuk".into()));
        }
        if h.proposer_idx != self.proposer_for(h.number, h.round) {
            return Err(ZagrosError::Other(format!(
                "baslik proposer_idx {} != rotasyon(h, {})",
                h.proposer_idx, h.round
            )));
        }
        verify_signed_header(&p.signed, &self.domain, &self.set)?;
        if let Some(vr) = p.valid_round {
            if vr >= p.round {
                return Err(ZagrosError::Other(
                    "valid_round zarf turundan kucuk olmali".into(),
                ));
            }
        }
        if h.parent_hash != self.tip.hash {
            return Err(ZagrosError::Other("parent_hash tip ile uyusmuyor".into()));
        }
        match (&h.last_qc, &self.tip.qc) {
            (Some(qc), Some(_)) => {
                // Byte eşitliği ARANMAZ (farklı imzacı alt kümeleri olabilir);
                // kriptografik doğrulama tip'in kümesine karşı yapılır.
                verify_qc(qc, &self.domain, &self.tip_set)?;
            }
            (None, None) if self.height == 1 => {}
            _ => return Err(ZagrosError::Other("last_qc / tip.qc uyusmazligi".into())),
        }
        // §7: timestamp ∈ (parent.ts, now + max_clock_skew_ms]
        if h.timestamp_ms <= self.tip.timestamp_ms {
            return Err(ZagrosError::Other(
                "zaman damgasi ebeveynden buyuk degil".into(),
            ));
        }
        if h.timestamp_ms > now_ms.saturating_add(self.params.max_clock_skew_ms) {
            return Err(ZagrosError::Other(
                "zaman damgasi gelecekte (max_clock_skew_ms)".into(),
            ));
        }
        if h.tx_count as usize != p.txs.len() {
            return Err(ZagrosError::Other("tx_count govdeyle uyusmuyor".into()));
        }
        let tx_hashes: Vec<Hash> = p.txs.iter().map(|t| t.tx_id).collect();
        if h.tx_root != BlockHeaderV2::compute_tx_root(&tx_hashes) {
            return Err(ZagrosError::Other("tx_root govdeyle uyusmuyor".into()));
        }
        let actual_bytes = block_body_bytes(&p.txs);
        if actual_bytes != h.body_bytes as u64 {
            return Err(ZagrosError::Other(format!(
                "body_bytes {} != gercek {}",
                h.body_bytes, actual_bytes
            )));
        }
        if actual_bytes > self.params.max_block_bytes {
            return Err(ZagrosError::Other("govde max_block_bytes'i asiyor".into()));
        }
        for tx in &p.txs {
            if tx.chain_id != zagros_types::CHAIN_ID {
                return Err(ZagrosError::Other("govdede yabanci chain_id'li tx".into()));
            }
        }
        if self.verified.get(&p.block_hash()).copied() != Some(true) {
            let root = verifier.simulate(h, &p.txs, &p.bridge_proposals, &p.shadow_votes)?;
            if root != h.state_root {
                return Err(ZagrosError::Other(format!(
                    "state_root uyusmazligi: baslik 0x{} simulasyon 0x{}",
                    hex::encode(h.state_root),
                    hex::encode(root)
                )));
            }
        }
        Ok(())
    }

    fn on_vote(&mut self, v: Vote, now_ms: u64, verifier: &dyn BlockVerifier) -> Vec<Output> {
        let mut out = Vec::new();
        if v.shadow {
            // INV-L4: gölge oylar QC'ye/sayıma girmez (liveness kaydı G7).
            return vec![Output::Dropped("golge oy sayilmaz".into())];
        }
        if v.round > self.round + MAX_LOOKAHEAD_ROUNDS {
            return vec![Output::Dropped(format!(
                "oy cok ileri round {} (simdi {})",
                v.round, self.round
            ))];
        }
        if let Err(e) = verify_vote(&v, &self.domain, &self.set) {
            return vec![Output::Dropped(format!("oy imzasi: {e}"))];
        }
        // Eski tur oyları: yalnız sayım defterine girer (QC/POL için); hiçbir
        // adım geçişini tetiklemez (fail-closed: imza doğrulanmadan girmez).
        let book = match v.phase {
            VotePhase::Prevote => &mut self.prevotes,
            VotePhase::Precommit => &mut self.precommits,
        };
        let slot = book.entry(v.round).or_default();
        if let Some(existing) = slot.get(&v.validator_idx) {
            if existing.block_hash == v.block_hash {
                return vec![Output::Dropped("oy zaten alindi".into())];
            }
            let key = (v.validator_idx, v.round, v.phase.as_u8());
            if !self.evidence_seen.contains(&key) {
                self.evidence_seen.push(key);
                out.push(Output::Evidence(Evidence::DoubleVote {
                    a: existing.clone(),
                    b: v,
                }));
            }
            out.push(Output::Dropped(
                "ayni (h,r,phase) icin ikinci oy (equivocation)".into(),
            ));
            return out;
        }
        let vote_round = v.round;
        slot.insert(v.validator_idx, v);

        // f+1 validator daha yüksek turda ⇒ o tura atla (liveness; safety'yi
        // etkilemez, kilit korunur).
        if vote_round > self.round {
            let f = byzantine_tolerance(self.set.len()) as usize;
            if self.distinct_voters_at(vote_round) > f {
                out.extend(self.start_round(
                    vote_round,
                    now_ms,
                    Some(ViewChangeReason::RoundSkip),
                    verifier,
                ));
                return out;
            }
        }
        out.extend(self.try_advance(now_ms, verifier));
        out
    }

    fn distinct_voters_at(&self, round: u32) -> usize {
        let mut idxs: Vec<u16> = Vec::new();
        for book in [&self.prevotes, &self.precommits] {
            if let Some(m) = book.get(&round) {
                for i in m.keys() {
                    if !idxs.contains(i) {
                        idxs.push(*i);
                    }
                }
            }
        }
        idxs.len()
    }

    fn has_quorum_prevotes(&self, round: u32, hash: Hash) -> bool {
        let q = self.set.quorum().map(|q| q as usize).unwrap_or(usize::MAX);
        self.prevotes
            .get(&round)
            .map(|m| m.values().filter(|v| v.block_hash == hash).count() >= q)
            .unwrap_or(false)
    }

    /// Eşik kontrolleri (§7/§8). Her olaydan sonra çağrılır; idempotent.
    fn try_advance(&mut self, now_ms: u64, verifier: &dyn BlockVerifier) -> Vec<Output> {
        let mut out = Vec::new();
        if !self.round_active {
            return out;
        }
        let q = match self.set.quorum() {
            Ok(q) => q as usize,
            Err(e) => return vec![Output::Dropped(format!("quorum hesaplanamadi: {e}"))],
        };
        let round = self.round;

        // --- PREVOTE aşaması (yalnız mevcut tur) ---
        if let Some((hash, _)) = self.quorum_value(&self.prevotes, round, q) {
            if hash != NIL_HASH {
                let have_body = self.proposals.get(&round).map(|p| p.block_hash()) == Some(hash);
                if have_body {
                    // POL: valid değeri güncelle (Prevote ya da Precommit adımında).
                    if self.step != Step::Propose {
                        self.valid = Some((round, hash));
                        self.valid_proposal = self.proposals.get(&round).cloned();
                    }
                    if self.step == Step::Prevote {
                        self.locked = Some((round, hash));
                        self.step = Step::Precommit;
                        self.prevote_deadline = None;
                        out.extend(self.cast_vote(VotePhase::Precommit, hash, now_ms, verifier));
                    }
                }
                // Gövdesi elimizde olmayan değere Q prevote: öneri gelince
                // yeniden değerlendirilir.
            } else if self.step == Step::Prevote {
                self.step = Step::Precommit;
                self.prevote_deadline = None;
                out.extend(self.cast_vote(VotePhase::Precommit, NIL_HASH, now_ms, verifier));
            }
        }

        // --- QC: HERHANGİ turdan Q×PRECOMMIT(hash) ---
        // ⏱️ Grace: Q görüldü ama N oy tamam değilse `qc_grace_ms` kadar bekle
        // (N tamamlanırsa anında kapat). Güvenlik/eşik değişmez; yalnız kapanış
        // anı. Pencere precommit deadline'ına sığmıyorsa beklenmez (Clamped).
        if self.pending_qc.is_none() {
            let mut rounds: Vec<u32> = self.precommits.keys().copied().collect();
            rounds.sort_unstable();
            let n = self.set.len() as usize;
            for r in rounds {
                if let Some((hash, votes)) = self.quorum_value(&self.precommits, r, q) {
                    if hash == NIL_HASH {
                        continue;
                    }
                    let close = if votes.len() >= n {
                        if self.qc_grace_wait.is_some() {
                            QcClose::Full
                        } else {
                            QcClose::Immediate
                        }
                    } else if self.qc_grace_ms == 0 {
                        QcClose::Immediate
                    } else {
                        match self.qc_grace_wait {
                            Some((wr, wh, at)) if wr == r && wh == hash => {
                                if now_ms < at {
                                    break; // pencere açık: bekle (host `next_deadline()` ile tick eder)
                                }
                                QcClose::GraceExpired
                            }
                            _ => match self.qc_grace_deadline(now_ms) {
                                Some(at) => {
                                    self.qc_grace_wait = Some((r, hash, at));
                                    break;
                                }
                                None => QcClose::Clamped,
                            },
                        }
                    };
                    match build_qc(&votes, &self.domain, &self.set, self.height, r, hash) {
                        Ok(qc) => {
                            self.pending_qc = Some(qc);
                            self.qc_grace_wait = None;
                            self.last_qc_close = close;
                            break;
                        }
                        Err(e) => out.push(Output::Dropped(format!("QC kurulamadi: {e}"))),
                    }
                }
            }
        }
        if let Some(qc) = self.pending_qc.clone() {
            let body = self
                .proposals
                .values()
                .find(|p| p.block_hash() == qc.block_hash)
                .cloned()
                .or_else(|| {
                    self.valid_proposal
                        .clone()
                        .filter(|p| p.block_hash() == qc.block_hash)
                });
            if let Some(proposal) = body {
                // 🛡️ Gövde doğrulanmadan commit'e gidemez: ileri tur tamponu
                // `check_proposal`sız saklar ve gövde imza kapsamında değil; sahte
                // gövde sızsa state_root uyuşmazlığıyla uzaktan halt tetiklenirdi.
                // Şimdi doğrula: geçerse commit, geçmezse at (sync kurtarma gerçek gövdeyi getirir).
                if self.verified.get(&qc.block_hash).copied() != Some(true) {
                    match self.check_proposal(&proposal, now_ms, verifier) {
                        Ok(()) => {
                            self.verified.insert(qc.block_hash, true);
                        }
                        Err(e) => {
                            self.proposals
                                .retain(|_, p| p.block_hash() != qc.block_hash);
                            out.push(Output::Dropped(format!(
                                "QC govdesi dogrulanamadi, kopya atildi (sync bekleniyor): {e}"
                            )));
                            return out;
                        }
                    }
                }
                out.extend(self.commit(proposal, qc, now_ms));
                return out;
            }
        }

        // --- Q×PRECOMMIT(nil) mevcut turda ⇒ anında view-change (§8) ---
        if self.pending_qc.is_none() && self.step == Step::Precommit {
            if let Some((hash, _)) = self.quorum_value(&self.precommits, round, q) {
                if hash == NIL_HASH {
                    let next = round + 1;
                    out.extend(self.start_round(
                        next,
                        now_ms,
                        Some(ViewChangeReason::NilQuorum),
                        verifier,
                    ));
                }
            }
        }
        out
    }

    /// `round`'daki oylar arasında ≥Q aynı hash'li olan (varsa) değer ve oyları.
    fn quorum_value(
        &self,
        book: &HashMap<u32, HashMap<u16, Vote>>,
        round: u32,
        q: usize,
    ) -> Option<(Hash, Vec<Vote>)> {
        let votes = book.get(&round)?;
        let mut tally: HashMap<Hash, Vec<Vote>> = HashMap::new();
        for v in votes.values() {
            tally.entry(v.block_hash).or_default().push(v.clone());
        }
        // Deterministik seçim: eşik aşan tek hash olabilir (Q > N/2).
        let mut hit: Vec<(Hash, Vec<Vote>)> =
            tally.into_iter().filter(|(_, vs)| vs.len() >= q).collect();
        hit.sort_by_key(|a| a.0);
        hit.into_iter().next()
    }

    fn cast_vote(
        &mut self,
        phase: VotePhase,
        block_hash: Hash,
        now_ms: u64,
        verifier: &dyn BlockVerifier,
    ) -> Vec<Output> {
        let Some(my_idx) = self.identity.as_ref().map(|id| id.idx) else {
            // Gözlemci oy atmaz ama tur timer'ları aynı kuralla ilerler.
            let t = self.t_vote(self.round);
            match phase {
                VotePhase::Prevote if self.prevote_deadline.is_none() => {
                    self.prevote_deadline = Some(now_ms.saturating_add(t))
                }
                VotePhase::Precommit if self.precommit_deadline.is_none() => {
                    self.precommit_deadline = Some(now_ms.saturating_add(t))
                }
                _ => {}
            }
            return Vec::new();
        };
        // INV-C1: (h, r, step) başına tek oy, defter zaten bizi içeriyorsa yeniden atılmaz.
        let book = match phase {
            VotePhase::Prevote => &self.prevotes,
            VotePhase::Precommit => &self.precommits,
        };
        if book
            .get(&self.round)
            .map(|m| m.contains_key(&my_idx))
            .unwrap_or(false)
        {
            return Vec::new();
        }
        // 🛡️ Restart-güvenli çift-imza koruması: bu (h,r,step) için daha önce
        // (farklı blokla) imzaladıysak ya da geçmiş bir üçlüdeyse imzalama.
        let dsp_step = match phase {
            VotePhase::Prevote => 1u8,
            VotePhase::Precommit => 2u8,
        };
        if let Some(ds) = self.double_sign.as_mut() {
            if !ds.allow(self.height, self.round, dsp_step, block_hash) {
                tracing::warn!(
                    "🛡️ anti-equivocation: h={} r={} step={} oyu imzalanmadı (restart güvenliği)",
                    self.height,
                    self.round,
                    dsp_step
                );
                // 🛡️ Oy engellense bile timer kurulur: restart sonrası herkes aynı
                // (h,r,step)te engellenirse kimse view-change tetikleyemez, zincir round 0'da kilitlenirdi.
                let t = self.t_vote(self.round);
                match phase {
                    VotePhase::Prevote if self.prevote_deadline.is_none() => {
                        self.prevote_deadline = Some(now_ms.saturating_add(t))
                    }
                    VotePhase::Precommit if self.precommit_deadline.is_none() => {
                        self.precommit_deadline = Some(now_ms.saturating_add(t))
                    }
                    _ => {}
                }
                return Vec::new();
            }
        }
        let id = self
            .identity
            .as_ref()
            .expect("kimlik cast_vote başında doğrulandı");
        let mut vote = Vote {
            height: self.height,
            round: self.round,
            phase,
            block_hash,
            validator_idx: my_idx,
            shadow: false,
            sig: Vec::new(),
        };
        sign_vote(&id.keypair, &self.domain, self.set.epoch, &mut vote);
        // §8 "timer → r+1": oy atılınca o adımın timer'ı kurulur (Q oy
        // beklenmez), Q altında kalan dürüst node sonsuza kadar adımda kalmaz;
        // tur ilerler, commit yalnız QC ile (INV-C3).
        let t = self.t_vote(self.round);
        match phase {
            VotePhase::Prevote => {
                if self.prevote_deadline.is_none() {
                    self.prevote_deadline = Some(now_ms.saturating_add(t));
                }
            }
            VotePhase::Precommit => {
                if self.precommit_deadline.is_none() {
                    self.precommit_deadline = Some(now_ms.saturating_add(t));
                }
            }
        }
        let mut out = vec![Output::Broadcast(Message::Vote(vote.clone()))];
        // Kendi oyumuzu sayarız (aynı doğrulama yolundan).
        out.extend(self.on_vote(vote, now_ms, verifier));
        out
    }

    fn commit(&mut self, proposal: Proposal, qc: QuorumCertificate, now_ms: u64) -> Vec<Output> {
        let hash = proposal.block_hash();
        let rounds_used = self.round + 1;
        self.tip = ChainTip {
            height: self.height,
            hash,
            qc: Some(qc.clone()),
            timestamp_ms: proposal.signed.header.timestamp_ms,
        };
        self.tip_set = self.set.clone();
        self.tip_committed_at_ms = now_ms;
        self.stats.commits_total += 1;
        self.stats.last_commit_round = qc.round;
        let out = vec![Output::Commit(Box::new(CommittedBlock {
            proposal,
            qc,
            rounds_used,
            qc_close: self.last_qc_close,
        }))];
        self.qc_grace_wait = None;

        self.height += 1;
        self.round = 0;
        self.step = Step::Propose;
        self.round_active = false;
        self.locked = None;
        self.valid = None;
        self.valid_proposal = None;
        self.proposals.clear();
        self.verified.clear();
        self.prevotes.clear();
        self.precommits.clear();
        self.pending_qc = None;
        self.evidence_seen.clear();
        self.propose_ready_at = None;
        self.propose_deadline = None;
        self.prevote_deadline = None;
        self.precommit_deadline = None;
        // Yeni yükseklik: host `Commit`'i uyguladıktan sonra `start()` çağırır
        // (tur 0 + timer'lar + tampon oynatma orada).
        out
    }
}

#[cfg(test)]
mod double_sign_tests {
    use super::DoubleSignProtector;

    fn tmp_path(tag: &str) -> std::path::PathBuf {
        let ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("zagros-priv-state-{tag}-{ns}"))
    }

    #[test]
    fn monotonik_izin_ayni_blok_idempotent_farkli_blok_reddedilir() {
        let p = tmp_path("mono");
        let mut d = DoubleSignProtector::load(&p);
        let a = [1u8; 32];
        let b = [2u8; 32];
        // artan (h,r,step) hep izinli
        assert!(d.allow(1, 0, 0, a)); // propose
        assert!(d.allow(1, 0, 1, a)); // prevote
        assert!(d.allow(1, 0, 2, a)); // precommit
        assert!(d.allow(2, 0, 0, a)); // sonraki yükseklik
                                      // yeni tur (aynı yükseklik) > önceki tur/step
        assert!(d.allow(2, 1, 0, a));
        // aynı (h,r,step) + aynı blok → idempotent (deterministik imza)
        assert!(d.allow(2, 1, 0, a));
        // aynı (h,r,step) + FARKLI blok → equivocation, RED
        assert!(!d.allow(2, 1, 0, b));
        // geçmiş (h,r,step) → RED
        assert!(!d.allow(1, 0, 2, a));
        assert!(!d.allow(2, 0, 2, a));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn restart_kalicidir_yeniden_yukleme_gecmisi_reddeder() {
        let p = tmp_path("restart");
        let a = [7u8; 32];
        {
            let mut d = DoubleSignProtector::load(&p);
            assert!(d.allow(184, 1, 2, a)); // precommit imzaladık
        }
        // "restart": aynı yoldan taze yükle → watermark korunmalı
        let mut d2 = DoubleSignProtector::load(&p);
        // aynı yükseklikte daha düşük/eşit → RED (çift imza engellendi)
        assert!(!d2.allow(184, 0, 1, [9u8; 32])); // prevote r0 < precommit r1
        assert!(!d2.allow(184, 1, 2, [9u8; 32])); // aynı HRS farklı blok
                                                  // aynı HRS aynı blok → idempotent izin
        assert!(d2.allow(184, 1, 2, a));
        // ileri → izin
        assert!(d2.allow(185, 0, 0, a));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn bozuk_dosya_fail_closed() {
        // Bozuk dosya = watermark BİLİNMİYOR → imza YOK. Sessizce temiz
        // başlangıç saymak tam da elektrik kesintisi senaryosunda korumayı kapatır.
        let p = tmp_path("corrupt");
        std::fs::write(&p, b"gecersiz icerik").unwrap();
        let mut d = DoubleSignProtector::load(&p);
        assert!(
            !d.allow(1, 0, 0, [1u8; 32]),
            "bozuk dosyada imza reddedilmeli"
        );
        assert!(
            !d.allow(999, 5, 2, [2u8; 32]),
            "hicbir (h,r,step) izinli olmamali"
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn bos_dosya_fail_closed() {
        // Yarım kalmış yazımın en tipik kalıntısı sıfır uzunluklu dosyadır.
        let p = tmp_path("empty");
        std::fs::write(&p, b"").unwrap();
        let mut d = DoubleSignProtector::load(&p);
        assert!(
            !d.allow(1, 0, 0, [1u8; 32]),
            "bos dosyada imza reddedilmeli"
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn dosya_yoklugu_temiz_baslangictir() {
        // Dosyanın HİÇ olmaması ilk açılıştır; imza izinli olmalı ve watermark
        // diske yazılmalı (fsync'li persist yolunu da uçtan uca çalıştırır).
        let p = tmp_path("fresh");
        let _ = std::fs::remove_file(&p);
        let mut d = DoubleSignProtector::load(&p);
        assert!(d.allow(1, 0, 0, [1u8; 32]));
        let mut d2 = DoubleSignProtector::load(&p);
        assert!(
            !d2.allow(1, 0, 0, [9u8; 32]),
            "ayni (h,r,step) farkli hash reddedilmeli"
        );
        let _ = std::fs::remove_file(&p);
    }
}
