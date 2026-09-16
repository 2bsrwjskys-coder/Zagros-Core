//! BFT konsensüs mesajlarının ağ zarfı ve FAIL-CLOSED giriş kapısı.
//! `WireEnvelope` = `chain_id ‖ genesis_hash ‖ epoch ‖ Message`. `InboundGate`
//! boyut → decode → zincir/epoch → yükseklik → indeks → Ed25519 → tekrar/
//! equivocation süzer; karar `Accept` / `Ignore` (ceza yok) / `Reject` (P4 + `PeerLedger`).
//! `PeerId` yalnız taşıma kimliğidir; validator kimliği konsensüs anahtarıdır.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use zagros_consensus::engine::Message;
use zagros_crypto::{
    verify_digest, verify_heartbeat, verify_shadow_vote, verify_signed_header, verify_vote,
};
use zagros_primitives::{Address, Hash, Result, ZagrosError};
use zagros_types::consensus::{ActiveValidatorSet, ChainParams, ConsensusDomain};

pub const WIRE_VERSION: u8 = 1;
/// Gövde dışı sabit pay: başlık + QC (≤101 imza × 64 B + bitset) + zarf.
const WIRE_OVERHEAD_BYTES: usize = 256 * 1024;
/// Mevcut yüksekliğin kaç ilerisi kabul edilir (motor tamponuyla aynı).
const HEIGHT_LOOKAHEAD: u64 = 2;
/// `PeerLedger` varsayılan yasak eşiği (ardışık/birikimli Reject).
pub const DEFAULT_BAN_THRESHOLD: u32 = 8;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireEnvelope {
    pub version: u8,
    pub chain_id: u64,
    pub genesis_hash: Hash,
    pub epoch: u64,
    pub msg: Message,
}

impl WireEnvelope {
    pub fn new(domain: &ConsensusDomain, epoch: u64, msg: Message) -> Self {
        Self {
            version: WIRE_VERSION,
            chain_id: domain.chain_id,
            genesis_hash: domain.genesis_hash,
            epoch,
            msg,
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| ZagrosError::P2pError(format!("WireEnvelope serialize: {e}")))
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| ZagrosError::P2pError(format!("WireEnvelope decode: {e}")))
    }
}

/// Kabul edilecek azami zarf boyutu: `max_block_bytes` + sabit pay.
pub fn max_wire_bytes(params: &ChainParams) -> usize {
    (params.max_block_bytes as usize).saturating_add(WIRE_OVERHEAD_BYTES)
}

/// Kapının ihtiyaç duyduğu, sürücü (driver) tarafından her commit'te
/// güncellenen görünüm.
#[derive(Debug, Clone)]
pub struct GateView {
    pub domain: ConsensusDomain,
    pub set: ActiveValidatorSet,
    /// Motorun çalıştığı yükseklik (= tip + 1).
    pub height: u64,
    /// G8: Probation validator'ların (adres → pubkey) anlık görüntüsü, sürücü her
    /// commit'te tazeler; gölge oy imzaları `State`siz doğrulanır. Boşsa gölge oylar `Ignore`.
    pub probation: Vec<(Address, [u8; 32])>,
    /// ⏱️ Ölçüm: bu node'un kurduğu son QC, geç gelen
    /// precommit'lerin gecikmesini ölçmek için. `None` = henüz commit yok.
    pub last_qc: Option<LastQc>,
}

/// Son QC'nin ölçüm için gereken özeti (bkz. `GateView::last_qc`).
#[derive(Debug, Clone)]
pub struct LastQc {
    pub height: u64,
    pub round: u32,
    pub block_hash: Hash,
    pub formed_at_ms: u64,
    pub signers: Vec<u16>,
}

pub type SharedGateView = Arc<RwLock<GateView>>;

#[derive(Debug)]
pub enum Verdict {
    Accept(Box<Message>),
    Ignore(String),
    Reject(String),
}

impl Verdict {
    pub fn is_accept(&self) -> bool {
        matches!(self, Verdict::Accept(_))
    }
}

/// (tür, height, round, phase, validator_idx) → ilk görülen hash.
type SeenKey = (u8, u64, u32, u8, u16);

pub struct InboundGate {
    view: SharedGateView,
    max_bytes: usize,
    seen: HashMap<SeenKey, Hash>,
    /// Aynı anahtar için ikinci (farklı hash) mesaj bir kez geçer (kanıt);
    /// üçüncü ve sonrası düşer.
    equivocation_passed: HashSet<SeenKey>,
    seen_height: u64,
    /// 🚨 Heartbeat ayrı defter: heartbeat tekrar edilmek üzere tasarlanmıştır;
    /// `seen` yolu farklı `timestamp_ms` yüzünden "equivocation" sanıp düşürüyor,
    /// boşta zincir ilk bloğunu üretemiyordu. Yalnız monotonluk aranır; sel koruması hız limitinde.
    heartbeat_seen: HashMap<(u64, u32, u16), u64>,
    /// G8: ShadowVote dedup, (adres, height, round) → ilk görülen hash.
    /// `SeenKey`'in `u16` yuvası validator_idx'e bağlı (Probation üyeleri
    /// kümede indekslenmediği için uygun değil), ayrı, adres-anahtarlı bir
    /// defter.
    shadow_seen: HashMap<(Address, u64, u32), Hash>,
}

fn now_ms_wall() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl InboundGate {
    pub fn new(view: SharedGateView, max_bytes: usize) -> Self {
        Self {
            view,
            max_bytes,
            seen: HashMap::new(),
            equivocation_passed: HashSet::new(),
            seen_height: 0,
            heartbeat_seen: HashMap::new(),
            shadow_seen: HashMap::new(),
        }
    }

    pub fn view(&self) -> SharedGateView {
        self.view.clone()
    }

    fn gc(&mut self, height: u64) {
        if height > self.seen_height {
            self.seen.retain(|k, _| k.1 >= height);
            self.equivocation_passed.retain(|k| k.1 >= height);
            self.shadow_seen.retain(|k, _| k.1 >= height);
            self.heartbeat_seen.retain(|k, _| k.0 >= height);
            self.seen_height = height;
        }
    }

    /// G8: ShadowVote doğrulaması `State`siz, yalnız `view.probation`a karşı
    /// (ağ/DoS filtresi); nihai doğrulama blok yürütmesinde deterministik tekrarlanır.
    fn check_shadow_vote(
        &mut self,
        sv: &zagros_types::consensus::ShadowVoteAttestation,
        view: &GateView,
    ) -> Verdict {
        if !sv.vote.shadow {
            return Verdict::Reject("ShadowVote icindeki oy shadow=false".into());
        }
        let Some((_, pubkey)) = view
            .probation
            .iter()
            .find(|(a, _)| a.eq_ignore_ascii_case(&sv.address))
        else {
            // Bilinmeyen/henüz-Probation-olmayan adres, geç propagasyon ya
            // da yanlış iddia olabilir; ceza yok, yalnız yayılmaz.
            return Verdict::Ignore("adres su an bilinen Probation kumesinde degil".into());
        };
        if let Err(e) = verify_shadow_vote(&sv.vote, &view.domain, view.set.epoch, pubkey) {
            return Verdict::Reject(format!("shadow oy imzasi: {e}"));
        }
        let key = (
            sv.address.to_ascii_lowercase(),
            sv.vote.height,
            sv.vote.round,
        );
        match self.shadow_seen.get(&key) {
            None => {
                self.shadow_seen.insert(key, sv.vote.block_hash);
                Verdict::Accept(Box::new(Message::ShadowVote(sv.clone())))
            }
            Some(_) => Verdict::Ignore("shadow oy tekrari".into()),
        }
    }

    /// Ham gossip baytı için karar. Hiçbir dal "best effort" değildir.
    pub fn check(&mut self, bytes: &[u8]) -> Verdict {
        if bytes.len() > self.max_bytes {
            return Verdict::Reject(format!(
                "zarf {} B > tavan {} B",
                bytes.len(),
                self.max_bytes
            ));
        }
        let env = match WireEnvelope::decode(bytes) {
            Ok(e) => e,
            Err(e) => return Verdict::Reject(format!("cozulemedi: {e}")),
        };
        if env.version != WIRE_VERSION {
            return Verdict::Reject(format!("zarf surumu {} != {}", env.version, WIRE_VERSION));
        }
        let view = match self.view.read() {
            Ok(v) => v.clone(),
            Err(_) => return Verdict::Ignore("gate view kilidi zehirli".into()),
        };
        if env.chain_id != view.domain.chain_id {
            return Verdict::Reject(format!(
                "chain_id {} != {}",
                env.chain_id, view.domain.chain_id
            ));
        }
        if env.genesis_hash != view.domain.genesis_hash {
            return Verdict::Reject("genesis_hash uyusmuyor".into());
        }
        self.gc(view.height);
        let height = env.msg.height();
        if height < view.height && !matches!(env.msg, Message::ShadowVote(_)) {
            // ⏱️ ÖLÇÜM: son QC'nin yüksekliği/turu/hash'i için gelen ama QC'ye
            // girememiş precommit → gecikmeyi kaydet (imza doğrulanır; sahte
            // oy istatistiği kirletemez). Karar/yayılım DEĞİŞMEZ: yine Ignore.
            if let (Message::Vote(v), Some(lq)) = (&env.msg, &view.last_qc) {
                if v.phase == zagros_types::consensus::VotePhase::Precommit
                    && !v.shadow
                    && v.height == lq.height
                    && v.round == lq.round
                    && v.block_hash == lq.block_hash
                    && !lq.signers.contains(&v.validator_idx)
                    && v.validator_idx < view.set.len()
                    && verify_vote(v, &view.domain, &view.set).is_ok()
                {
                    let delta = now_ms_wall().saturating_sub(lq.formed_at_ms);
                    zagros_metrics::record_late_precommit(v.validator_idx, delta);
                    tracing::debug!(
                        "⏱️ gec precommit h={} r={} idx={} +{}ms",
                        v.height,
                        v.round,
                        v.validator_idx,
                        delta
                    );
                }
            }
            return Verdict::Ignore(format!("bayat yukseklik {} < {}", height, view.height));
        }
        if height > view.height.saturating_add(HEIGHT_LOOKAHEAD) {
            return Verdict::Ignore(format!(
                "cok ileri yukseklik {} (simdi {})",
                height, view.height
            ));
        }
        if env.epoch != view.set.epoch {
            // Epoch geçişinde dürüst bir peer geçici olarak farklı epoch'ta
            // olabilir, imza bu epoch'a bağlı olduğundan doğrulanamaz; ceza yok.
            return Verdict::Ignore(format!("epoch {} != {}", env.epoch, view.set.epoch));
        }
        let n = view.set.len();
        if n == 0 {
            return Verdict::Ignore("aktif kume bos".into());
        }
        let proposer_for = |h: u64, r: u32| ((h + r as u64) % n as u64) as u16;

        if let Message::ShadowVote(sv) = &env.msg {
            return self.check_shadow_vote(sv, &view);
        }

        let (key, hash) = match &env.msg {
            Message::Vote(v) => {
                if v.shadow {
                    // G8: gölge oylar kendi `Message::ShadowVote` varyantıyla gelir;
                    // shadow=true normal Vote format ihlalidir (Reject, INV-L4).
                    return Verdict::Reject(
                        "shadow=true normal Vote uzerinden gonderilemez".into(),
                    );
                }
                if v.validator_idx >= n {
                    return Verdict::Reject(format!(
                        "validator_idx {} kume disinda",
                        v.validator_idx
                    ));
                }
                if let Err(e) = verify_vote(v, &view.domain, &view.set) {
                    return Verdict::Reject(format!("oy imzasi: {e}"));
                }
                (
                    (0u8, v.height, v.round, v.phase.as_u8(), v.validator_idx),
                    v.block_hash,
                )
            }
            Message::Heartbeat(hb) => {
                if hb.validator_idx >= n {
                    return Verdict::Reject(format!(
                        "validator_idx {} kume disinda",
                        hb.validator_idx
                    ));
                }
                if hb.validator_idx != proposer_for(hb.height, hb.round) {
                    return Verdict::Reject("heartbeat lider olmayan validator'dan".into());
                }
                if let Err(e) = verify_heartbeat(hb, &view.domain, &view.set) {
                    return Verdict::Reject(format!("heartbeat imzasi: {e}"));
                }
                // Equivocation defterine GİRMEZ (yukarıdaki alan yorumu):
                // yalnız damga monotonluğu aranır.
                let hb_key = (hb.height, hb.round, hb.validator_idx);
                let stale = matches!(self.heartbeat_seen.get(&hb_key), Some(last) if hb.timestamp_ms <= *last);
                if stale {
                    return Verdict::Ignore("heartbeat tekrari (eski/ayni damga)".into());
                }
                self.heartbeat_seen.insert(hb_key, hb.timestamp_ms);
                return Verdict::Accept(Box::new(env.msg));
            }
            Message::Proposal(p) => {
                let hdr = &p.signed.header;
                let expected = proposer_for(hdr.number, p.round);
                let Some(pk) = view.set.pubkey_of(expected) else {
                    return Verdict::Reject("proposer indeksi kume disinda".into());
                };
                if let Err(e) =
                    verify_digest(pk, &p.envelope_digest(&view.domain, view.set.epoch), &p.sig)
                {
                    return Verdict::Reject(format!("oneri zarf imzasi: {e}"));
                }
                if hdr.proposer_idx != proposer_for(hdr.number, hdr.round) {
                    return Verdict::Reject("baslik proposer_idx rotasyonla uyusmuyor".into());
                }
                if let Err(e) = verify_signed_header(&p.signed, &view.domain, &view.set) {
                    return Verdict::Reject(format!("baslik imzasi: {e}"));
                }
                ((1u8, hdr.number, p.round, 0, expected), p.block_hash())
            }
            Message::ShadowVote(_) => unreachable!("yukarida erken donuldu"),
        };

        match self.seen.get(&key) {
            None => {
                self.seen.insert(key, hash);
                Verdict::Accept(Box::new(env.msg))
            }
            Some(first) if *first == hash => Verdict::Ignore("tekrar (duplicate)".into()),
            Some(_) => {
                if self.equivocation_passed.insert(key) {
                    // İkinci farklı mesaj: motor kanıt üretsin diye BİR kez geçer.
                    Verdict::Accept(Box::new(env.msg))
                } else {
                    Verdict::Ignore("equivocation tekrari".into())
                }
            }
        }
    }
}

/// PeerId bazlı kötü davranış defteri: Reject +1, Accept −1, eşikte yasak (süreç ömrü).
/// 🛡️ Üst sınırlar zorunlu: `PeerId` üretmek bedava, sınırsız defterde saldırgan
/// her seferinde yeni kimlikle belleği uzaktan büyütürdü. Sınır aşımında güvenlik
/// kademeli bozulur (atılan yasak yeniden ihlalde konur), çökmez.
const MAX_TRACKED_PEERS: usize = 4_096;
const MAX_BANNED_PEERS: usize = 4_096;

#[derive(Debug, Default)]
pub struct PeerLedger {
    rejects: HashMap<PeerId, u32>,
    banned: HashSet<PeerId>,
    /// Yasakların FIFO sırası, sınır aşılınca EN ESKİ yasak düşürülür.
    /// `HashSet` sıra tutmadığı için ayrı bir kuyruk gerekiyor.
    ban_order: std::collections::VecDeque<PeerId>,
    ban_threshold: u32,
}

impl PeerLedger {
    pub fn new(ban_threshold: u32) -> Self {
        Self {
            rejects: HashMap::new(),
            banned: HashSet::new(),
            ban_order: std::collections::VecDeque::new(),
            ban_threshold: ban_threshold.max(1),
        }
    }
    pub fn is_banned(&self, peer: &PeerId) -> bool {
        self.banned.contains(peer)
    }
    /// `true` = bu kayıtla yasak eşiği aşıldı (çağıran bağlantıyı kessin).
    pub fn record_reject(&mut self, peer: PeerId) -> bool {
        let c = self.rejects.entry(peer).or_insert(0);
        *c += 1;
        let crossed = *c >= self.ban_threshold;
        if crossed {
            // Yasaklanan peer'ın sayaç girdisine artık gerek yok, yasak kümesi
            // zaten onu tutuyor; ikisini birden tutmak boşuna yer.
            self.rejects.remove(&peer);
            if self.banned.insert(peer) {
                self.ban_order.push_back(peer);
                while self.ban_order.len() > MAX_BANNED_PEERS {
                    if let Some(oldest) = self.ban_order.pop_front() {
                        self.banned.remove(&oldest);
                    }
                }
            }
        }
        self.prune_if_oversized();
        crossed
    }
    pub fn record_accept(&mut self, peer: &PeerId) {
        // 🛡️ Sayaç 0'a indiğinde girdi TAMAMEN SİLİNİR; 0 değerinde asılı
        // kalsaydı dürüst bir ağda bile defter, ömrü boyunca görülen HER peer
        // kadar büyürdü.
        if let Some(c) = self.rejects.get_mut(peer) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.rejects.remove(peer);
            }
        }
    }
    pub fn reject_count(&self, peer: &PeerId) -> u32 {
        self.rejects.get(peer).copied().unwrap_or(0)
    }

    /// Sayaç haritası tavanı aşarsa, kanıtı EN ZAYIF olanları (tek ihlal)
    /// düşürür. Yetmezse tamamen boşaltır, sınırlı bellek, kademeli güvenlik.
    fn prune_if_oversized(&mut self) {
        if self.rejects.len() <= MAX_TRACKED_PEERS {
            return;
        }
        self.rejects.retain(|_, c| *c > 1);
        if self.rejects.len() > MAX_TRACKED_PEERS {
            self.rejects.clear();
        }
    }

    /// Yalnızca test/teşhis: defterin fiili boyutları.
    pub fn sizes(&self) -> (usize, usize) {
        (self.rejects.len(), self.banned.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zagros_consensus::engine::{BftEngine, BlockVerifier, ChainTip, NodeIdentity, Output};
    use zagros_crypto::{sign_heartbeat, sign_vote, ConsensusKeypair};
    use zagros_executor::bridge::BridgeProposal;
    use zagros_types::consensus::{
        BlockHeaderV2, Heartbeat, ValidatorMember, Vote, VotePhase, NIL_HASH,
    };
    use zagros_types::{Transaction, CHAIN_ID};

    struct FakeVerifier;
    impl BlockVerifier for FakeVerifier {
        fn simulate(
            &self,
            h: &BlockHeaderV2,
            _t: &[Transaction],
            _b: &[BridgeProposal],
            _sv: &[zagros_types::consensus::ShadowVoteAttestation],
        ) -> Result<Hash> {
            Ok(h.parent_hash)
        }
    }

    fn kps() -> Vec<ConsensusKeypair> {
        (0..4u8)
            .map(|i| ConsensusKeypair::from_secret_bytes(&[i + 1; 32]))
            .collect()
    }
    fn set(kps: &[ConsensusKeypair]) -> ActiveValidatorSet {
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
    fn domain() -> ConsensusDomain {
        ConsensusDomain::new(CHAIN_ID, [7u8; 32])
    }
    fn gate() -> (InboundGate, Vec<ConsensusKeypair>) {
        let k = kps();
        let view = Arc::new(RwLock::new(GateView {
            domain: domain(),
            set: set(&k),
            height: 1,
            probation: Vec::new(),
            last_qc: None,
        }));
        (
            InboundGate::new(view, max_wire_bytes(&ChainParams::genesis_defaults())),
            k,
        )
    }
    fn vote(k: &ConsensusKeypair, idx: u16, height: u64, round: u32, hash: Hash) -> Message {
        let mut v = Vote {
            height,
            round,
            phase: VotePhase::Prevote,
            block_hash: hash,
            validator_idx: idx,
            shadow: false,
            sig: vec![],
        };
        sign_vote(k, &domain(), 0, &mut v);
        Message::Vote(v)
    }
    fn wire(msg: Message) -> Vec<u8> {
        WireEnvelope::new(&domain(), 0, msg).encode().unwrap()
    }

    /// 🚨 Canlılık regresyonu: tekrar eden heartbeat "equivocation" sanılıp
    /// düşürülüyor, boşta zincir ilk bloğunu üretemiyordu.
    #[test]
    fn repeated_heartbeats_from_the_leader_keep_being_accepted() {
        let (mut g, k) = gate();
        // Rotasyon: lider = (height + round) % N -> h=1, r=0 icin 1
        let leader: u16 = 1;
        let mut accepted = 0;
        for ts in [1_000u64, 1_100, 1_200, 1_300, 1_400] {
            let mut hb = Heartbeat {
                height: 1,
                round: 0,
                timestamp_ms: ts,
                validator_idx: leader,
                sig: vec![],
            };
            sign_heartbeat(&k[leader as usize], &domain(), 0, &mut hb);
            if g.check(&wire(Message::Heartbeat(hb))).is_accept() {
                accepted += 1;
            }
        }
        assert_eq!(
            accepted, 5,
            "ardisik heartbeat'lerin HEPSI kabul edilmeli (tur canli kalmali)"
        );
    }

    /// Sel/tekrar-oynatma koruması yine de kalmalı: AYNI ya da ESKİ damga geçmez.
    #[test]
    fn a_replayed_or_older_heartbeat_is_ignored() {
        let (mut g, k) = gate();
        let leader: u16 = 1;
        let mk = |ts: u64| {
            let mut hb = Heartbeat {
                height: 1,
                round: 0,
                timestamp_ms: ts,
                validator_idx: leader,
                sig: vec![],
            };
            sign_heartbeat(&k[leader as usize], &domain(), 0, &mut hb);
            wire(Message::Heartbeat(hb))
        };
        assert!(g.check(&mk(2_000)).is_accept());
        assert!(
            !g.check(&mk(2_000)).is_accept(),
            "ayni damga tekrar gecmemeli"
        );
        assert!(!g.check(&mk(1_999)).is_accept(), "eski damga gecmemeli");
        assert!(g.check(&mk(2_001)).is_accept(), "daha yeni damga gecmeli");
    }

    #[test]
    fn valid_vote_is_accepted_once_and_duplicate_ignored() {
        let (mut g, k) = gate();
        let bytes = wire(vote(&k[1], 1, 1, 0, [1; 32]));
        assert!(g.check(&bytes).is_accept());
        assert!(matches!(g.check(&bytes), Verdict::Ignore(r) if r.contains("duplicate")));
    }

    #[test]
    fn equivocating_vote_passes_once_then_is_ignored() {
        let (mut g, k) = gate();
        assert!(g.check(&wire(vote(&k[1], 1, 1, 0, [1; 32]))).is_accept());
        assert!(
            g.check(&wire(vote(&k[1], 1, 1, 0, [2; 32]))).is_accept(),
            "kanit icin bir kez"
        );
        assert!(matches!(
            g.check(&wire(vote(&k[1], 1, 1, 0, [3; 32]))),
            Verdict::Ignore(_)
        ));
    }

    #[test]
    fn wrong_chain_genesis_version_signature_or_index_is_rejected() {
        let (mut g, k) = gate();
        let mut env = WireEnvelope::new(&domain(), 0, vote(&k[1], 1, 1, 0, [1; 32]));
        env.chain_id += 1;
        assert!(
            matches!(g.check(&env.encode().unwrap()), Verdict::Reject(r) if r.contains("chain_id"))
        );
        let mut env = WireEnvelope::new(&domain(), 0, vote(&k[1], 1, 1, 0, [1; 32]));
        env.genesis_hash = [8; 32];
        assert!(
            matches!(g.check(&env.encode().unwrap()), Verdict::Reject(r) if r.contains("genesis"))
        );
        let mut env = WireEnvelope::new(&domain(), 0, vote(&k[1], 1, 1, 0, [1; 32]));
        env.version = 9;
        assert!(
            matches!(g.check(&env.encode().unwrap()), Verdict::Reject(r) if r.contains("surumu"))
        );
        // yanlış anahtarla imzalanmış oy (idx 1, anahtar 2)
        assert!(
            matches!(g.check(&wire(vote(&k[2], 1, 1, 0, [1; 32]))), Verdict::Reject(r) if r.contains("imza"))
        );
        // küme dışı indeks
        assert!(
            matches!(g.check(&wire(vote(&k[0], 9, 1, 0, [1; 32]))), Verdict::Reject(r) if r.contains("kume disinda"))
        );
        // çözülemeyen bayt
        assert!(matches!(g.check(b"\xff\xff\xff"), Verdict::Reject(r) if r.contains("cozulemedi")));
    }

    /// 🚨 Tehdit modeli: P2P'ye bağlanmak oy hakkı vermez; imza zincirdeki
    /// kümeden okunan anahtarla doğrulanır. Kümede olmayan anahtarla üç saldırı
    /// (indeks taklidi, küme dışı indeks, sahte heartbeat) reddedilmeli.
    #[test]
    fn a_key_that_is_not_in_the_validator_set_cannot_get_anything_accepted() {
        let (mut g, k) = gate();
        // Kümede OLMAYAN anahtar: set() yalnız [1;32]..[4;32] tohumlarını kullanır.
        let yabanci = ConsensusKeypair::from_secret_bytes(&[99u8; 32]);
        assert!(
            !set(&k)
                .members
                .iter()
                .any(|m| m.consensus_pubkey == yabanci.public_key()),
            "yabanci anahtar kazara kumede olmamali"
        );

        // 1) Geçerli bir indeksi (0) taklit et, imza o üyenin anahtarına ait
        //    olmadığı için düşer.
        assert!(
            matches!(g.check(&wire(vote(&yabanci, 0, 1, 0, [7; 32]))), Verdict::Reject(r) if r.contains("imza")),
            "yabanci anahtarla atilan oy REDDEDILMELI"
        );

        // 2) Küme dışı bir indeks uydur, imza doğrulamasına bile gelmeden düşer.
        assert!(
            matches!(g.check(&wire(vote(&yabanci, 4, 1, 0, [7; 32]))), Verdict::Reject(r) if r.contains("kume disinda")),
            "kume disi indeks REDDEDILMELI"
        );

        // 3) Lider gibi heartbeat yolla, aynı kapıdan döner.
        let mut hb = Heartbeat {
            height: 1,
            round: 0,
            validator_idx: 0,
            timestamp_ms: 1,
            sig: Vec::new(),
        };
        sign_heartbeat(&yabanci, &domain(), 0, &mut hb);
        assert!(
            matches!(g.check(&wire(Message::Heartbeat(hb))), Verdict::Reject(_)),
            "yabanci heartbeat REDDEDILMELI"
        );

        // Kontrol: aynı mesaj GERÇEK üyenin anahtarıyla gönderilince KABUL edilir.
        // Böylece testin "her şeyi reddediyor" diye boşuna geçmediği kanıtlanır.
        assert!(
            g.check(&wire(vote(&k[0], 0, 1, 0, [7; 32]))).is_accept(),
            "gercek uyenin oyu KABUL edilmeli"
        );
    }

    /// ⏱️ Ölçüm: son QC'nin (h, r, hash) için QC dışı kalmış imzalı precommit
    /// gecikme defterine yazılır; karar yine Ignore (yayılmaz, ceza yok).
    /// Prevote, başka hash, zaten-imzacı ya da sahte imza YAZILMAZ.
    #[test]
    fn late_precommit_for_last_qc_is_measured_but_still_ignored() {
        let (mut g, k) = gate();
        let hash = [9u8; 32];
        {
            let shared = g.view();
            let mut v = shared.write().unwrap();
            v.height = 2; // motor 2'de; QC h=1 r=0 kapandı, imzacılar 0,1,2 (idx 3 dışarıda)
            v.last_qc = Some(LastQc {
                height: 1,
                round: 0,
                block_hash: hash,
                formed_at_ms: 1,
                signers: vec![0, 1, 2],
            });
        }
        let precommit = |kp: &ConsensusKeypair, idx: u16, h: Hash| {
            let mut v = Vote {
                height: 1,
                round: 0,
                phase: VotePhase::Precommit,
                block_hash: h,
                validator_idx: idx,
                shadow: false,
                sig: vec![],
            };
            sign_vote(kp, &domain(), 0, &mut v);
            Message::Vote(v)
        };
        let before = zagros_metrics::late_vote_stats_json();
        // gerçek geç oy → yazılır
        assert!(
            matches!(g.check(&wire(precommit(&k[3], 3, hash))), Verdict::Ignore(r) if r.contains("bayat"))
        );
        let after = zagros_metrics::late_vote_stats_json();
        assert!(
            after.contains(r#""idx":3"#) && after.contains(r#""late":1"#),
            "{after}"
        );
        assert_ne!(before, after);
        // zaten imzacı olan (idx 1), farklı hash ve sahte imza → yazılmaz
        assert!(matches!(
            g.check(&wire(precommit(&k[1], 1, hash))),
            Verdict::Ignore(_)
        ));
        assert!(matches!(
            g.check(&wire(precommit(&k[3], 3, [8u8; 32]))),
            Verdict::Ignore(_)
        ));
        assert!(matches!(
            g.check(&wire(precommit(&k[2], 3, hash))),
            Verdict::Ignore(_)
        )); // idx 3 iddiası, k[2] imzası
        let after2 = zagros_metrics::late_vote_stats_json();
        assert_eq!(after, after2, "yalniz gecerli gec oy sayilmali");
    }

    #[test]
    fn oversized_envelope_is_rejected_before_decode() {
        let (mut g, _) = gate();
        let big = vec![0u8; max_wire_bytes(&ChainParams::genesis_defaults()) + 1];
        assert!(matches!(g.check(&big), Verdict::Reject(r) if r.contains("tavan")));
    }

    #[test]
    fn stale_far_future_and_other_epoch_are_ignored_without_penalty() {
        let (mut g, k) = gate();
        assert!(
            matches!(g.check(&wire(vote(&k[1], 1, 0, 0, [1; 32]))), Verdict::Ignore(r) if r.contains("bayat"))
        );
        assert!(
            matches!(g.check(&wire(vote(&k[1], 1, 9, 0, [1; 32]))), Verdict::Ignore(r) if r.contains("ileri"))
        );
        let env = WireEnvelope::new(&domain(), 5, vote(&k[1], 1, 1, 0, [1; 32]));
        assert!(
            matches!(g.check(&env.encode().unwrap()), Verdict::Ignore(r) if r.contains("epoch"))
        );
    }

    /// G8: `shadow=true` bir normal `Message::Vote` üzerinden gelirse (yanlış
    /// format, gölge oylar KENDİ `Message::ShadowVote` varyantıyla taşınır)
    /// Reject edilir, Ignore DEĞİL, çünkü bu format ihlali kanıtlanabilir bir
    /// protokol hatasıdır (INV-L4'ün wire-seviyesi karşılığı).
    #[test]
    fn shadow_flagged_vote_sent_as_a_plain_vote_message_is_rejected() {
        let (mut g, k) = gate();
        let mut v = Vote {
            height: 1,
            round: 0,
            phase: VotePhase::Prevote,
            block_hash: NIL_HASH,
            validator_idx: 1,
            shadow: true,
            sig: vec![],
        };
        sign_vote(&k[1], &domain(), 0, &mut v);
        assert!(
            matches!(g.check(&wire(Message::Vote(v))), Verdict::Reject(r) if r.contains("shadow=true"))
        );
    }

    #[test]
    fn heartbeat_only_from_rotation_leader_with_valid_signature() {
        let (mut g, k) = gate();
        // h=1 r=0 lider = 1
        let mut hb = Heartbeat {
            height: 1,
            round: 0,
            timestamp_ms: 5,
            validator_idx: 1,
            sig: vec![],
        };
        sign_heartbeat(&k[1], &domain(), 0, &mut hb);
        assert!(g.check(&wire(Message::Heartbeat(hb.clone()))).is_accept());
        assert!(matches!(
            g.check(&wire(Message::Heartbeat(hb))),
            Verdict::Ignore(_)
        ));
        let mut bad = Heartbeat {
            height: 1,
            round: 0,
            timestamp_ms: 6,
            validator_idx: 2,
            sig: vec![],
        };
        sign_heartbeat(&k[2], &domain(), 0, &mut bad);
        assert!(
            matches!(g.check(&wire(Message::Heartbeat(bad))), Verdict::Reject(r) if r.contains("lider"))
        );
    }

    #[test]
    fn proposal_requires_envelope_and_header_signatures_from_rotation_proposer() {
        let (mut g, k) = gate();
        let s = set(&k);
        let tip = ChainTip {
            height: 0,
            hash: [9; 32],
            qc: None,
            timestamp_ms: 0,
        };
        let mut e = BftEngine::new(
            domain(),
            ChainParams::genesis_defaults(),
            s.clone(),
            Some(NodeIdentity {
                idx: 1,
                keypair: ConsensusKeypair::from_secret_bytes(&k[1].secret_bytes()),
            }),
            tip,
            None,
        )
        .unwrap();
        e.start(1_000, &FakeVerifier);
        let outs = e
            .propose(1_500, vec![], vec![], vec![], &FakeVerifier)
            .unwrap();
        let p = outs
            .iter()
            .find_map(|o| match o {
                Output::Broadcast(Message::Proposal(p)) => Some((**p).clone()),
                _ => None,
            })
            .unwrap();
        assert!(g
            .check(&wire(Message::Proposal(Box::new(p.clone()))))
            .is_accept());
        // zarf imzası bozuk
        let mut bad = p.clone();
        bad.sig[0] ^= 1;
        assert!(
            matches!(g.check(&wire(Message::Proposal(Box::new(bad)))), Verdict::Reject(r) if r.contains("zarf"))
        );
        // başlık imzası bozuk (zarf doğru kalsın diye yeniden imzala)
        let mut bad = p.clone();
        bad.signed.sig[0] ^= 1;
        bad.sig = k[1].sign_digest(&bad.envelope_digest(&domain(), 0));
        assert!(
            matches!(g.check(&wire(Message::Proposal(Box::new(bad)))), Verdict::Reject(r) if r.contains("baslik"))
        );
    }

    fn gate_with_probation(
        probation_kp: &ConsensusKeypair,
        probation_addr: &str,
    ) -> (InboundGate, Vec<ConsensusKeypair>) {
        let k = kps();
        let view = Arc::new(RwLock::new(GateView {
            domain: domain(),
            set: set(&k),
            height: 1,
            probation: vec![(probation_addr.to_string(), probation_kp.public_key())],
            last_qc: None,
        }));
        (
            InboundGate::new(view, max_wire_bytes(&ChainParams::genesis_defaults())),
            k,
        )
    }
    fn shadow_wire(
        address: &str,
        kp: &ConsensusKeypair,
        epoch: u64,
        height: u64,
        round: u32,
    ) -> (Vec<u8>, Vote) {
        let mut v = Vote {
            height,
            round,
            phase: VotePhase::Prevote,
            block_hash: [3u8; 32],
            validator_idx: 0,
            shadow: true,
            sig: vec![],
        };
        sign_vote(kp, &domain(), epoch, &mut v);
        let sv = zagros_types::consensus::ShadowVoteAttestation {
            address: address.to_string(),
            vote: v.clone(),
        };
        let bytes = WireEnvelope::new(&domain(), 0, Message::ShadowVote(sv))
            .encode()
            .unwrap();
        (bytes, v)
    }

    #[test]
    fn shadow_vote_from_a_known_probation_address_is_accepted_once_then_deduped() {
        let probation_kp = ConsensusKeypair::from_secret_bytes(&[99; 32]);
        let addr = "0x00000000000000000000000000000000000099";
        let (mut g, _k) = gate_with_probation(&probation_kp, addr);
        let (bytes, _) = shadow_wire(addr, &probation_kp, 0, 1, 0);
        assert!(g.check(&bytes).is_accept());
        assert!(matches!(g.check(&bytes), Verdict::Ignore(r) if r.contains("tekrar")));
    }

    #[test]
    fn shadow_vote_with_forged_signature_is_rejected() {
        let probation_kp = ConsensusKeypair::from_secret_bytes(&[99; 32]);
        let addr = "0x00000000000000000000000000000000000099";
        let (mut g, _k) = gate_with_probation(&probation_kp, addr);
        let (mut bytes, v) = shadow_wire(addr, &probation_kp, 0, 1, 0);
        let _ = v;
        // Zarf içindeki imza baytını boz (decode edilebilir kalsın diye
        // dosyanın son baytlarından birini çevir, sig genelde sonda).
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        // Bozuk bayt hâlâ decode edilebiliyorsa Reject, edilemiyorsa da Reject
        // (ikisi de kabul edilebilir, yalnız Accept OLMAMALI).
        assert!(!g.check(&bytes).is_accept());
    }

    #[test]
    fn shadow_vote_signed_by_a_different_key_than_the_claimed_address_is_rejected() {
        let probation_kp = ConsensusKeypair::from_secret_bytes(&[99; 32]);
        let addr = "0x00000000000000000000000000000000000099";
        let (mut g, _k) = gate_with_probation(&probation_kp, addr);
        let wrong_kp = ConsensusKeypair::from_secret_bytes(&[88; 32]);
        let (bytes, _) = shadow_wire(addr, &wrong_kp, 0, 1, 0);
        assert!(matches!(g.check(&bytes), Verdict::Reject(r) if r.contains("imza")));
    }

    #[test]
    fn shadow_vote_from_an_address_not_currently_known_as_probation_is_ignored_without_penalty() {
        let probation_kp = ConsensusKeypair::from_secret_bytes(&[99; 32]);
        let (mut g, _k) =
            gate_with_probation(&probation_kp, "0x00000000000000000000000000000000000099");
        let unknown_addr = "0x00000000000000000000000000000000000077";
        let (bytes, _) = shadow_wire(unknown_addr, &probation_kp, 0, 1, 0);
        assert!(matches!(g.check(&bytes), Verdict::Ignore(r) if r.contains("Probation")));
    }

    #[test]
    fn shadow_vote_with_shadow_flag_false_is_rejected() {
        let probation_kp = ConsensusKeypair::from_secret_bytes(&[99; 32]);
        let addr = "0x00000000000000000000000000000000000099";
        let (mut g, _k) = gate_with_probation(&probation_kp, addr);
        let mut v = Vote {
            height: 1,
            round: 0,
            phase: VotePhase::Prevote,
            block_hash: [3u8; 32],
            validator_idx: 0,
            shadow: false,
            sig: vec![],
        };
        sign_vote(&probation_kp, &domain(), 0, &mut v);
        let sv = zagros_types::consensus::ShadowVoteAttestation {
            address: addr.to_string(),
            vote: v,
        };
        let bytes = WireEnvelope::new(&domain(), 0, Message::ShadowVote(sv))
            .encode()
            .unwrap();
        assert!(matches!(g.check(&bytes), Verdict::Reject(r) if r.contains("shadow=false")));
    }

    #[test]
    fn shadow_vote_replayed_for_a_different_round_is_accepted_independently() {
        let probation_kp = ConsensusKeypair::from_secret_bytes(&[99; 32]);
        let addr = "0x00000000000000000000000000000000000099";
        let (mut g, _k) = gate_with_probation(&probation_kp, addr);
        let (b1, _) = shadow_wire(addr, &probation_kp, 0, 1, 0);
        let (b2, _) = shadow_wire(addr, &probation_kp, 0, 1, 1);
        assert!(g.check(&b1).is_accept());
        assert!(
            g.check(&b2).is_accept(),
            "farkli round bagimsiz kabul edilmeli"
        );
    }

    #[test]
    fn peer_ledger_bans_after_threshold_and_decays_on_accept() {
        let mut l = PeerLedger::new(3);
        let p = PeerId::random();
        assert!(!l.record_reject(p));
        l.record_accept(&p);
        assert_eq!(l.reject_count(&p), 0);
        assert!(!l.record_reject(p));
        assert!(!l.record_reject(p));
        assert!(l.record_reject(p), "3. reject → yasak");
        assert!(l.is_banned(&p));
    }

    fn random_peer() -> PeerId {
        PeerId::random()
    }

    /// 🚨 REGRESYON: `PeerId` bir Ed25519 açık
    /// anahtarıdır, üretmesi BEDAVADIR. Defter sınırsız olsaydı saldırgan her
    /// seferinde YENİ bir kimlikle bağlanıp tek geçersiz mesaj atarak düğümün
    /// belleğini UZAKTAN, sınırsız büyütebilirdi.
    #[test]
    fn the_peer_ledger_stays_bounded_under_unlimited_identity_churn() {
        let mut ledger = PeerLedger::new(DEFAULT_BAN_THRESHOLD);
        // Tavanin cok uzerinde, HER BIRI FARKLI kimlikten tek ihlal.
        for _ in 0..(MAX_TRACKED_PEERS * 3) {
            ledger.record_reject(random_peer());
        }
        let (tracked, banned) = ledger.sizes();
        assert!(
            tracked <= MAX_TRACKED_PEERS,
            "sayac haritasi sinirsiz buyudu: {tracked}"
        );
        assert!(
            banned <= MAX_BANNED_PEERS,
            "yasak kumesi sinirsiz buyudu: {banned}"
        );
    }

    /// Yasak kümesi de sınırlı olmalı: tavanı aşan sayıda peer yasaklansa bile
    /// bellek sabit kalır (en eski yasak düşer, peer yeniden ihlal ederse
    /// yeniden yasaklanır).
    #[test]
    fn the_ban_set_is_bounded_and_evicts_the_oldest_ban_first() {
        let mut ledger = PeerLedger::new(1); // tek ihlalde yasak
        let first = random_peer();
        ledger.record_reject(first);
        assert!(ledger.is_banned(&first), "ilk peer yasaklanmali");

        for _ in 0..MAX_BANNED_PEERS {
            ledger.record_reject(random_peer());
        }
        let (_, banned) = ledger.sizes();
        assert!(
            banned <= MAX_BANNED_PEERS,
            "yasak kumesi sinirsiz: {banned}"
        );
        assert!(
            !ledger.is_banned(&first),
            "tavan asilinca EN ESKI yasak dusmeli (FIFO)"
        );
    }

    /// 🛡️ Dürüst bir ağda bile defter büyümemeli: sayaç 0'a indiğinde girdi
    /// TAMAMEN silinir (0 değerinde asılı kalsaydı düğüm ömrü boyunca gördüğü
    /// her peer kadar yer tutardı).
    #[test]
    fn a_peer_that_recovers_leaves_no_entry_behind() {
        let mut ledger = PeerLedger::new(DEFAULT_BAN_THRESHOLD);
        let peer = random_peer();
        ledger.record_reject(peer);
        assert_eq!(ledger.reject_count(&peer), 1);
        assert_eq!(ledger.sizes().0, 1);

        ledger.record_accept(&peer);
        assert_eq!(ledger.reject_count(&peer), 0);
        assert_eq!(
            ledger.sizes().0,
            0,
            "sayac sifirlaninca girdi TAMAMEN silinmeli"
        );
    }

    /// Sınırlama, ASIL işlevi bozmamalı: eşiğe ulaşan peer hâlâ yasaklanır.
    #[test]
    fn bounding_the_ledger_does_not_weaken_the_ban_threshold() {
        let mut ledger = PeerLedger::new(3);
        let peer = random_peer();
        assert!(!ledger.record_reject(peer), "1. ihlal yasaklamamali");
        assert!(!ledger.record_reject(peer), "2. ihlal yasaklamamali");
        assert!(ledger.record_reject(peer), "3. ihlalde yasaklanmali");
        assert!(ledger.is_banned(&peer));
    }
}
