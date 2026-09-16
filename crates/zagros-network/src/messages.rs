//! Gossip mesaj zarfları. `Transaction` (zagros-types) zaten `Serialize`/
//! `Deserialize` türetiyor, burada sadece bincode ile taşınacak zarf tipi
//! tanımlanıyor, yeni bir serileştirme şeması İCAT edilmiyor.

use libp2p::gossipsub::IdentTopic;
use serde::{Deserialize, Serialize};
use zagros_executor::bridge::BridgeProposal;
use zagros_primitives::Hash;
use zagros_types::consensus::{QuorumCertificate, ShadowVoteAttestation, SignedHeader};
use zagros_types::{ArchivedBlockHeader, Transaction};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipMessage {
    NewTransaction(Transaction),
    /// Proposer'ın az önce ürettiği blok. `header.parent_hash`/`tx_hashes`
    /// alıcı tarafında KULLANILMAZ, follower kendi header'ını sıfırdan
    /// türetir (bkz. `Runtime::apply_external_block`'un doc yorumu); sadece
    /// `header.number`/`timestamp`/`state_root` ve `transactions` taşınır.
    NewBlock {
        header: ArchivedBlockHeader,
        transactions: Vec<Transaction>,
        /// 🛡️ P2P follower senkronizasyon hatası kök-neden düzeltmesi
        /// - bkz. `zagros_executor::bridge::collect_bridge_proposals`/
        /// `ingest_bridge_proposals`.
        bridge_proposals: Vec<BridgeProposal>,
    },
}

/// `network_id` (= CHAIN_ID) topic adına gömülür ki yanlışlıkla farklı bir
/// ağa (örn. yerel bir test node'u) bağlanan bir peer asla cross-talk yapmasın.
pub fn tx_topic(network_id: u64) -> IdentTopic {
    IdentTopic::new(format!("/zagros/{network_id}/txs/1"))
}

/// Aynı isimlendirme kuralı, proposer'ın ürettiği blokların yayınlandığı topic.
pub fn block_topic(network_id: u64) -> IdentTopic {
    IdentTopic::new(format!("/zagros/{network_id}/blocks/1"))
}

/// G5: BFT konsensüs mesajları (Proposal/Vote/Heartbeat, `WireEnvelope`).
pub fn consensus_topic(network_id: u64) -> IdentTopic {
    IdentTopic::new(format!("/zagros/{network_id}/consensus/1"))
}

/// 🛡️ Sentry duyuruları. AYRI topic: eski düğümler abone değil,
/// gossipsub konu bazlı yaydığı için onlara hiç ulaşmaz → tel formatı
/// uyumsuzluğu yok, kural kapısı gerekmez.
pub fn peers_topic(network_id: u64) -> IdentTopic {
    IdentTopic::new(format!("/zagros/{network_id}/peers/1"))
}

/// Validatörün sentry adreslerini duyurusu; konsensüs anahtarıyla imzalanır,
/// alıcı zincirdeki `consensus_pubkey` ile doğrular. Kimse elle liste düzenlemez.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerAnnouncement {
    /// Validatörün hesap adresi (0x…, küçük harf).
    pub validator: String,
    /// Sentry adresleri (multiaddr, `/p2p/<PeerId>` ile). En fazla 8.
    pub sentries: Vec<String>,
    /// Duyurunun yapıldığı epoch (bilgi/sıralama için).
    pub epoch: u64,
    /// Unix saniye; alıcı `issued_at` daha yeni olanı tutar, eskisini atar.
    pub issued_at: u64,
    /// Ed25519 imza (64 bayt), `signing_digest` üzerinde.
    pub sig: Vec<u8>,
}

impl PeerAnnouncement {
    pub const MAX_SENTRIES: usize = 8;
    /// Duyuru bu süreden eskiyse (saniye) güvenilmez, kayıttan düşer.
    pub const TTL_SECS: u64 = 3 * 3600;

    /// Domain-separated digest: etiket + chain_id + genesis_hash + alanlar.
    pub fn signing_digest(&self, domain: &zagros_types::consensus::ConsensusDomain) -> Hash {
        // Zincirin diğer imzalarıyla aynı aile: keccak256 (zagros-types).
        let mut buf: Vec<u8> = Vec::with_capacity(256);
        buf.extend_from_slice(b"zagros/peer-announce/1");
        buf.extend_from_slice(&domain.chain_id.to_le_bytes());
        buf.extend_from_slice(&domain.genesis_hash);
        buf.extend_from_slice(self.validator.to_ascii_lowercase().as_bytes());
        buf.extend_from_slice(&self.epoch.to_le_bytes());
        buf.extend_from_slice(&self.issued_at.to_le_bytes());
        buf.extend_from_slice(&(self.sentries.len() as u32).to_le_bytes());
        for a in &self.sentries {
            buf.extend_from_slice(&(a.len() as u32).to_le_bytes());
            buf.extend_from_slice(a.as_bytes());
        }
        zagros_types::consensus::keccak256(&buf)
    }

    /// Yapısal doğrulama (imzadan bağımsız): adres biçimi, sayı, boyut.
    pub fn validate_shape(&self) -> Result<(), String> {
        if self.sentries.is_empty() || self.sentries.len() > Self::MAX_SENTRIES {
            return Err(format!("sentry sayisi 1..{} olmali", Self::MAX_SENTRIES));
        }
        if !self.validator.starts_with("0x") || self.validator.len() != 42 {
            return Err("validator adresi 0x + 40 hex olmali".into());
        }
        for a in &self.sentries {
            if a.len() > 200 || !a.starts_with('/') || !a.contains("/p2p/") {
                return Err(format!("gecersiz sentry adresi: {a}"));
            }
            a.parse::<libp2p::Multiaddr>()
                .map_err(|e| format!("multiaddr: {e}"))?;
        }
        if self.sig.len() != 64 {
            return Err("imza 64 bayt olmali".into());
        }
        Ok(())
    }
}

/// `/zagros/sync/1` mesaj tipleri: gossip'te boşluk görülünce geriye dönük
/// yakalama. Herhangi bir node cevap verebilir (`block_<N>` kayıtları aynı).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncRequest {
    /// Karşı tarafın mevcut zincir tepe noktasını sorar (bilgi amaçlı/gelecekte
    /// kullanılabilir, şu an `sync.rs`'in durum makinesi tarafından
    /// tüketilmiyor, ama protokolün ileride genişleyebilmesi için tanımlı).
    GetStatus,
    /// `[from, to]` KAPSAYICI aralık, yanıtlayan `sync_batch_size`'a göre
    /// kırpabilir (bkz. `SyncResponse::BlockRange`'in doc yorumu).
    GetBlockRange { from: u64, to: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncResponse {
    Status {
        tip_number: u64,
    },
    /// İstenenden DAHA AZ blok dönebilir (`sync_batch_size` sınırı), istemci
    /// tepe noktaya ulaşana kadar tekrar istemeye devam eder (bkz. `sync.rs`).
    BlockRange(Vec<SyncBlock>),
    /// İstenen `from` bu node'da hiç yok (ör. budanmış/pruned bir node'a
    /// sorulduysa), istemci başka bir peer denemeli.
    NotAvailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncBlock {
    pub header: ArchivedBlockHeader,
    pub transactions: Vec<Transaction>,
    /// 🛡️ Follower senkronu için (`collect_bridge_proposals`/`ingest_bridge_proposals`).
    /// `#[serde(default)]` kasıtlı yok: bincode kendini tanımlamaz, tüm node'lar birlikte yükseltilir.
    pub bridge_proposals: Vec<BridgeProposal>,
}

// G6: `/zagros/sync/2`, QC'li point-to-point catch-up (spec §9). `/sync/1`
// (tek-proposer, QC'siz) DEĞİŞMEDİ; bu protokol ayrı ve açıkça QC'li.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Sync2Request {
    GetStatus,
    /// `[from, to]` kapsayıcı; yanıtlayan `sync_batch_size`'a kırpar.
    GetBlockRange {
        from: u64,
        to: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sync2Status {
    pub tip_height: u64,
    pub tip_hash: Hash,
    pub epoch: u64,
    pub validator_set_hash: Hash,
}

/// Catch-up bloğu: kesinleşmiş başlık + o bloğun QC'si + gövde. Alıcı HER
/// alanı yeniden doğrular (QC imzaları, başlık kuralları, tx_root, yeniden
/// yürütme kök eşitliği), hiçbir alan güvenilir kabul edilmez (INV-Y1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sync2Block {
    pub signed: SignedHeader,
    pub qc: QuorumCertificate,
    pub transactions: Vec<Transaction>,
    pub bridge_proposals: Vec<BridgeProposal>,
    /// G8: bu bloğa gömülü ShadowVote'lar, yeniden yürütme AYNI state_root'u
    /// üretebilsin diye (bkz. `sync2::store_consensus_records`).
    #[serde(default)]
    pub shadow_votes: Vec<ShadowVoteAttestation>,
}

/// Gövdesi hiçbir peer'da olmayan işlemler içeren blok; `missing` = (sıra, tx_id).
/// tx_root mevcut+eksik birleşik listeden doğrulanır, doğruluk yeniden yürütme
/// kök eşitliğiyle kanıtlanır (eksikler state'e dokunmamış olmalı).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sync2BlockV2 {
    pub block: Sync2Block,
    pub missing: Vec<(u32, Hash)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Sync2Response {
    Status(Sync2Status),
    Blocks(Vec<Sync2Block>),
    NotAvailable,
    /// Yalnız partide en az bir bloğun gövdesi eksikse kullanılır (eski peer'lar
    /// bu varyantı çözemez → "yanıt çözülemedi", başka peer'a geçerler).
    BlocksV2(Vec<Sync2BlockV2>),
}
