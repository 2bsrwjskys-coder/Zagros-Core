//! Konsensüs veri tipleri (§3, §5, §6, §13-14): biçimler, yapısal doğrulama,
//! digest, zincir parametreleri. Fail-closed. `BlockHeaderV2::VERSION = 2`.

use serde::{Deserialize, Serialize};
use zagros_primitives::{Result, ZagrosError};

use crate::{Address, Hash};

// DOMAIN SEPARATION (§6)

/// İmzalanan her konsensüs mesajının etiketi. Farklı etiket = farklı digest →
/// bir mesajın imzası başka bir mesaj türü için asla geçerli olamaz (INV-D1).
pub const DOMAIN_VOTE: &[u8] = b"ZAGROS/VOTE/v1";
pub const DOMAIN_SHADOW: &[u8] = b"ZAGROS/SHADOW/v1";
pub const DOMAIN_HEADER: &[u8] = b"ZAGROS/HEADER/v1";
pub const DOMAIN_HEARTBEAT: &[u8] = b"ZAGROS/HEARTBEAT/v1";
pub const DOMAIN_KEYOWN: &[u8] = b"ZAGROS/KEYOWN/v1";
pub const DOMAIN_KEYROT: &[u8] = b"ZAGROS/KEYROT/v1";

/// "nil" blok hash'i (PREVOTE(nil) / PRECOMMIT(nil) = view-change oyu).
pub const NIL_HASH: Hash = [0u8; 32];

/// Bir zincir örneğini tanımlayan imza bağlamı: `chain_id` + `genesis_hash`.
/// Testnet/mainnet ve fork'lar arası replay'i imkânsız kılar (§16).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusDomain {
    pub chain_id: u64,
    pub genesis_hash: Hash,
}

impl ConsensusDomain {
    pub fn new(chain_id: u64, genesis_hash: Hash) -> Self {
        Self {
            chain_id,
            genesis_hash,
        }
    }
}

/// Kanonik imza yükü (bayt dizisi):
/// `TAG ‖ chain_id(u64 LE) ‖ genesis_hash(32) ‖ epoch(u64 LE) ‖ height(u64 LE) ‖ round(u32 LE) ‖ phase(u8) ‖ block_hash(32)`.
/// Her alan sabit genişlikte → iki farklı alan kümesi aynı yükü üretemez.
pub fn signing_payload(
    tag: &[u8],
    domain: &ConsensusDomain,
    epoch: u64,
    height: u64,
    round: u32,
    phase: u8,
    block_hash: &Hash,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(tag.len() + 8 + 32 + 8 + 8 + 4 + 1 + 32);
    v.extend_from_slice(tag);
    v.extend_from_slice(&domain.chain_id.to_le_bytes());
    v.extend_from_slice(&domain.genesis_hash);
    v.extend_from_slice(&epoch.to_le_bytes());
    v.extend_from_slice(&height.to_le_bytes());
    v.extend_from_slice(&round.to_le_bytes());
    v.push(phase);
    v.extend_from_slice(block_hash);
    v
}

/// İmzalanan 32 baytlık digest = keccak256(signing_payload).
pub fn signing_digest(
    tag: &[u8],
    domain: &ConsensusDomain,
    epoch: u64,
    height: u64,
    round: u32,
    phase: u8,
    block_hash: &Hash,
) -> Hash {
    keccak256(&signing_payload(
        tag, domain, epoch, height, round, phase, block_hash,
    ))
}

pub fn keccak256(bytes: &[u8]) -> Hash {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&out);
    hash
}

// VALIDATOR SET + QUORUM MATEMATİĞİ (§3)

/// Tek işlemin bincode boyutu, blok gövde tavanı (`max_block_bytes`) için
/// kanonik ölçü; mempool, proposer ve doğrulayıcı AYNI fonksiyonu kullanır.
pub fn transaction_encoded_size(tx: &crate::Transaction) -> u64 {
    bincode::serialized_size(tx).unwrap_or(u64::MAX)
}

/// Blok gövdesinin (işlem listesi) kanonik bayt boyutu = `bincode(Vec<Transaction>)`
/// = 8 (uzunluk öneki) + Σ `transaction_encoded_size`. `BlockHeaderV2.body_bytes`
/// bu değerdir.
pub fn block_body_bytes(txs: &[crate::Transaction]) -> u64 {
    bincode::serialized_size(txs).unwrap_or(u64::MAX)
}

pub const MAX_VALIDATORS_HARD: u16 = 101;

/// §23 (G10): bu binary'nin desteklediği en yüksek kural seti; zincirdeki
/// `active_ruleset` bunu aşarsa node FAIL-CLOSED durur. Binary eski seti de
/// taşır (dual-ruleset). Ruleset 2: sıkıştırılmış tel formatı; ruleset 1 iken
/// eski düzen yazılır, arşivdeki eski kayıtlar her iki durumda okunur, böylece
/// yeni binary oylamadan önce kesintisiz kurulabilir.
pub const SUPPORTED_RULESET: u32 = 2;
/// BFT'nin anlamlı olduğu asgari küme (N<4 → f=0; INV-S1).
pub const MIN_VALIDATORS: u16 = 4;

/// f = ⌊(N−1)/3⌋ — tolere edilen Byzantine/offline validator sayısı.
pub fn byzantine_tolerance(n: u16) -> u16 {
    if n == 0 {
        0
    } else {
        (n - 1) / 3
    }
}

/// Q = ⌊2N/3⌋ + 1 (">2/3 of N"); `n < MIN_VALIDATORS` için `Err`.
/// 🚨 Spec'in "Q = 2f+1"i yalnız N = 3f+1 için doğrudur; genel kesişim koşulu
/// `2Q − N ≥ f + 1` (INV-C2) ⌊2N/3⌋+1 gerektirir (N=5 → 4, N=51 → 35).
pub fn quorum_of(n: u16) -> Result<u16> {
    if n < MIN_VALIDATORS {
        return Err(ZagrosError::Other(format!(
            "validator kumesi BFT icin cok kucuk: N={n} < {MIN_VALIDATORS}"
        )));
    }
    if n > MAX_VALIDATORS_HARD {
        return Err(ZagrosError::Other(format!(
            "validator kumesi kod tavanini asiyor: N={n} > {MAX_VALIDATORS_HARD}"
        )));
    }
    Ok((2 * n) / 3 + 1)
}

/// Validator lifecycle durumu (§2). `Candidate` = kayıtlı ama onaysız.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorStatus {
    Candidate,
    Approved,
    Probation,
    Active,
    Jailed,
    Exiting,
    Removed,
}

/// Onboarding beyanları (§2.2). Zincir-dışı doğrulanır; tavanlar zincir-üstü
/// uygulanır. `operator_id` bir kimliğin hash'idir (gizlilik).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ValidatorDeclaration {
    pub provider: String,
    pub region: String,
    pub asn: u32,
    pub operator_id: Hash,
}

/// Aktif kümedeki tek bir üye: hesap adresi + epoch için geçerli Ed25519
/// konsensüs anahtarı. `validator_idx` = bu vektördeki sıra.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorMember {
    pub address: Address,
    pub consensus_pubkey: [u8; 32],
}

/// Epoch e'nin aktif kümesi `V_e` (§3). Üyeler kayıt sırasına göre sıralıdır;
/// `hash()` epoch + sıralı pubkey'lerden türetilir ve her header'da taşınır.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveValidatorSet {
    pub epoch: u64,
    pub members: Vec<ValidatorMember>,
}

impl ActiveValidatorSet {
    pub fn len(&self) -> u16 {
        self.members.len() as u16
    }
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
    pub fn quorum(&self) -> Result<u16> {
        quorum_of(self.len())
    }
    /// `validator_set_hash_e = keccak(epoch LE ‖ sorted(consensus_pubkeys))`.
    /// Sıralama pubkey baytlarına göre, üye sırasından bağımsız, deterministik.
    pub fn hash(&self) -> Hash {
        let mut keys: Vec<[u8; 32]> = self.members.iter().map(|m| m.consensus_pubkey).collect();
        keys.sort_unstable();
        let mut buf = Vec::with_capacity(8 + keys.len() * 32);
        buf.extend_from_slice(&self.epoch.to_le_bytes());
        for k in &keys {
            buf.extend_from_slice(k);
        }
        keccak256(&buf)
    }
    pub fn pubkey_of(&self, idx: u16) -> Option<&[u8; 32]> {
        self.members.get(idx as usize).map(|m| &m.consensus_pubkey)
    }
    /// Yapısal geçerlilik: boyut sınırları, tekrar eden pubkey/adres yok.
    pub fn validate(&self) -> Result<()> {
        quorum_of(self.len())?;
        let mut seen_keys = std::collections::HashSet::new();
        let mut seen_addr = std::collections::HashSet::new();
        for m in &self.members {
            if !seen_keys.insert(m.consensus_pubkey) {
                return Err(ZagrosError::Other(
                    "validator kumesinde tekrar eden consensus_pubkey".into(),
                ));
            }
            if !seen_addr.insert(m.address.to_ascii_lowercase()) {
                return Err(ZagrosError::Other(
                    "validator kumesinde tekrar eden adres".into(),
                ));
            }
            if m.consensus_pubkey == [0u8; 32] {
                return Err(ZagrosError::Other("sifir consensus_pubkey".into()));
            }
        }
        Ok(())
    }
}

// VOTE / HEADER / QC / HEARTBEAT / EVIDENCE (§5)

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum VotePhase {
    Prevote = 1,
    Precommit = 2,
}

impl VotePhase {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Tek bir validator oyu. `shadow = true` → Probation "gölge" oyu: QC'ye
/// GİREMEZ, yalnız liveness ölçümüne sayılır (INV-L4). Domain etiketi shadow
/// bayrağına göre seçilir (§6), böylece gölge oy gerçek oy gibi kullanılamaz.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    pub height: u64,
    pub round: u32,
    pub phase: VotePhase,
    pub block_hash: Hash,
    pub validator_idx: u16,
    pub shadow: bool,
    pub sig: Vec<u8>,
}

impl Vote {
    pub fn is_nil(&self) -> bool {
        self.block_hash == NIL_HASH
    }
    pub fn domain_tag(&self) -> &'static [u8] {
        if self.shadow {
            DOMAIN_SHADOW
        } else {
            DOMAIN_VOTE
        }
    }
    pub fn signing_digest(&self, domain: &ConsensusDomain, epoch: u64) -> Hash {
        signing_digest(
            self.domain_tag(),
            domain,
            epoch,
            self.height,
            self.round,
            self.phase.as_u8(),
            &self.block_hash,
        )
    }
}

/// Blok başlığı v2 (§5). Hash kuralı: `keccak256(bincode(header))`, mevcut
/// `ArchivedBlockHeader` kuralıyla aynı ilke (kendi hash'ini içermez).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeaderV2 {
    pub version: u8,
    pub number: u64,
    pub parent_hash: Hash,
    /// S1: proposer'ın deterministik yürütme sonucu; her validator yeniden
    /// yürütüp karşılaştırır (INV-P2/P3).
    pub state_root: Hash,
    pub timestamp_ms: u64,
    pub tx_root: Hash,
    pub tx_count: u32,
    pub body_bytes: u32,
    pub epoch: u64,
    pub validator_set_hash: Hash,
    pub round: u32,
    pub proposer_idx: u16,
    /// §23 (G10): üreticinin desteklediği en yüksek kural seti beyanı; her commit'te
    /// state'e işlenir, ≥%80 hazırlık buradan okunur.
    pub max_ruleset: u32,
    /// Ebeveyn bloğun QC'si (genesis'te `None`). Zincir kendi kesinliğini taşır.
    pub last_qc: Option<QuorumCertificate>,
}

impl BlockHeaderV2 {
    pub const VERSION: u8 = 2;

    pub fn hash(&self) -> Hash {
        let bytes = bincode::serialize(self).expect("BlockHeaderV2 serileştirilebilir");
        keccak256(&bytes)
    }

    /// `tx_root = keccak(tx_hash_1 ‖ tx_hash_2 ‖ …)` (sıralı).
    pub fn compute_tx_root(tx_hashes: &[Hash]) -> Hash {
        let mut buf = Vec::with_capacity(tx_hashes.len() * 32);
        for h in tx_hashes {
            buf.extend_from_slice(h);
        }
        keccak256(&buf)
    }

    /// Öneri imzası digest'i: HEADER etiketi, phase=0, block_hash=header hash.
    pub fn signing_digest(&self, domain: &ConsensusDomain) -> Hash {
        signing_digest(
            DOMAIN_HEADER,
            domain,
            self.epoch,
            self.number,
            self.round,
            0,
            &self.hash(),
        )
    }

    /// Yapısal kurallar (imza/yürütme hariç; bkz. §7 kabul kuralları).
    pub fn validate_structure(&self, params: &ChainParams) -> Result<()> {
        if self.version != Self::VERSION {
            return Err(ZagrosError::Other(format!(
                "header surumu {} != {}",
                self.version,
                Self::VERSION
            )));
        }
        if self.body_bytes as u64 > params.max_block_bytes {
            return Err(ZagrosError::Other(format!(
                "blok govdesi {} > max_block_bytes {}",
                self.body_bytes, params.max_block_bytes
            )));
        }
        if self.number == 0 {
            return Err(ZagrosError::Other("yukseklik 0 yalniz genesis'tir".into()));
        }
        // §23: yürürlükteki kural setinden düşük beyanlı başlık üretilemez —
        // eski yazılım zaten fail-closed durur; böyle bir başlık ancak bozuk/
        // kötü niyetlidir.
        if self.max_ruleset < params.active_ruleset {
            return Err(ZagrosError::Other(format!(
                "baslik max_ruleset {} < aktif kural seti {} (eski surum blok uretemez)",
                self.max_ruleset, params.active_ruleset
            )));
        }
        match &self.last_qc {
            None if self.number > 1 => {
                return Err(ZagrosError::Other(
                    "genesis disinda her blok last_qc tasimali".into(),
                ))
            }
            Some(qc) => {
                if qc.height + 1 != self.number {
                    return Err(ZagrosError::Other(format!(
                        "last_qc yuksekligi {} ebeveyn degil (blok {})",
                        qc.height, self.number
                    )));
                }
                if qc.block_hash != self.parent_hash {
                    return Err(ZagrosError::Other(
                        "last_qc.block_hash != parent_hash".into(),
                    ));
                }
            }
            None => {}
        }
        Ok(())
    }
}

/// İmzalı başlık: proposer'ın konsensüs anahtarıyla `header.signing_digest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedHeader {
    pub header: BlockHeaderV2,
    pub sig: Vec<u8>,
}

/// Quorum Certificate (§5): bir (height, round, block_hash) için ≥Q
/// PRECOMMIT imzası. `signers` bit kümesi (validator_idx bitleri), `sigs`
/// set bit sırasıyla imzalar. Gölge oylar GİREMEZ (INV-L4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    pub height: u64,
    pub round: u32,
    pub block_hash: Hash,
    pub epoch: u64,
    pub validator_set_hash: Hash,
    pub signers: Vec<u8>,
    pub sigs: Vec<Vec<u8>>,
}

impl QuorumCertificate {
    pub fn bitset_len_for(n: u16) -> usize {
        (n as usize).div_ceil(8)
    }
    pub fn signer_indices(&self) -> Vec<u16> {
        let mut out = Vec::new();
        for (byte_i, b) in self.signers.iter().enumerate() {
            for bit in 0..8u8 {
                if b & (1 << bit) != 0 {
                    out.push((byte_i * 8 + bit as usize) as u16);
                }
            }
        }
        out
    }
    pub fn set_signer(bitset: &mut [u8], idx: u16) {
        bitset[idx as usize / 8] |= 1 << (idx % 8);
    }
    /// Yapısal doğrulama (imzasız): nil hash yok, bit kümesi boyutu, indeks
    /// sınırı, imza sayısı = set bit sayısı, sayı ≥ Q. İmza doğrulaması
    /// `zagros-crypto::verify_qc`'dedir; ikisi birlikte INV-Q1'i verir.
    pub fn validate_structure(&self, set: &ActiveValidatorSet) -> Result<()> {
        let n = set.len();
        let q = set.quorum()?;
        if self.block_hash == NIL_HASH {
            return Err(ZagrosError::Other("QC nil hash tasiyamaz".into()));
        }
        if self.epoch != set.epoch {
            return Err(ZagrosError::Other(format!(
                "QC epoch {} != kume epoch {}",
                self.epoch, set.epoch
            )));
        }
        if self.validator_set_hash != set.hash() {
            return Err(ZagrosError::Other(
                "QC validator_set_hash kume ile uyusmuyor".into(),
            ));
        }
        if self.signers.len() != Self::bitset_len_for(n) {
            return Err(ZagrosError::Other(
                "QC bitset boyutu kume boyutuyla uyusmuyor".into(),
            ));
        }
        let idxs = self.signer_indices();
        if idxs.iter().any(|i| *i >= n) {
            return Err(ZagrosError::Other("QC imzaci indeksi kume disinda".into()));
        }
        if idxs.len() != self.sigs.len() {
            return Err(ZagrosError::Other(format!(
                "QC imza sayisi {} != imzaci biti {}",
                self.sigs.len(),
                idxs.len()
            )));
        }
        if (idxs.len() as u16) < q {
            return Err(ZagrosError::Other(format!(
                "QC quorum altinda: {} < {}",
                idxs.len(),
                q
            )));
        }
        Ok(())
    }
}

/// Boşta liveness sinyali (§4, §7). Oy değildir, QC'ye girmez.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    pub height: u64,
    pub round: u32,
    pub timestamp_ms: u64,
    pub validator_idx: u16,
    pub sig: Vec<u8>,
}

/// G8 (§4): Probation validator'ının gölge oyu, imzalayan adresle eşleşmiş
/// taşıma zarfı; `Vote` değişmedi. Bloğa gömme `bridge_proposals` ilkesiyle:
/// proposer toplar, her doğrulayıcı kendisi doğrulayıp `state_root`a işler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowVoteAttestation {
    pub address: Address,
    pub vote: Vote,
}

impl Heartbeat {
    pub fn signing_digest(&self, domain: &ConsensusDomain, epoch: u64) -> Hash {
        let mut ts = [0u8; 32];
        ts[..8].copy_from_slice(&self.timestamp_ms.to_le_bytes());
        signing_digest(
            DOMAIN_HEARTBEAT,
            domain,
            epoch,
            self.height,
            self.round,
            0,
            &ts,
        )
    }
}

/// Equivocation kanıtı (§11). Yapısal kural: aynı (height, round, phase,
/// validator), iki FARKLI block_hash. İmza doğrulaması `zagros-crypto`'da.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Evidence {
    DoubleVote {
        a: Vote,
        b: Vote,
    },
    DoublePropose {
        a: Box<SignedHeader>,
        b: Box<SignedHeader>,
    },
}

impl Evidence {
    pub fn height(&self) -> u64 {
        match self {
            Evidence::DoubleVote { a, .. } => a.height,
            Evidence::DoublePropose { a, .. } => a.header.number,
        }
    }
    pub fn validator_idx(&self) -> u16 {
        match self {
            Evidence::DoubleVote { a, .. } => a.validator_idx,
            Evidence::DoublePropose { a, .. } => a.header.proposer_idx,
        }
    }
    pub fn validate_structure(&self) -> Result<()> {
        match self {
            Evidence::DoubleVote { a, b } => {
                if a.height != b.height
                    || a.round != b.round
                    || a.phase != b.phase
                    || a.validator_idx != b.validator_idx
                {
                    return Err(ZagrosError::Other(
                        "DoubleVote: (height, round, phase, validator) ayni olmali".into(),
                    ));
                }
                if a.shadow != b.shadow {
                    return Err(ZagrosError::Other(
                        "DoubleVote: shadow bayraklari farkli".into(),
                    ));
                }
                if a.block_hash == b.block_hash {
                    return Err(ZagrosError::Other(
                        "DoubleVote: ayni block_hash, equivocation degil".into(),
                    ));
                }
                if a.sig == b.sig {
                    return Err(ZagrosError::Other("DoubleVote: ayni imza".into()));
                }
                Ok(())
            }
            Evidence::DoublePropose { a, b } => {
                let (ha, hb) = (&a.header, &b.header);
                if ha.number != hb.number
                    || ha.round != hb.round
                    || ha.proposer_idx != hb.proposer_idx
                {
                    return Err(ZagrosError::Other(
                        "DoublePropose: (height, round, proposer) ayni olmali".into(),
                    ));
                }
                if ha.hash() == hb.hash() {
                    return Err(ZagrosError::Other("DoublePropose: ayni header".into()));
                }
                Ok(())
            }
        }
    }
}

// G2: LIFECYCLE PAYLOAD'LARI, ADMIN MULTISIG, SENTINEL ANAHTARLAR (§2, §15, §16)

/// State sentinel anahtarları (hesap `contract_code` = bincode(değer)).
pub const GENESIS_HASH_KEY: &str = "__GENESIS_HASH__";
pub const ADMIN_MULTISIG_KEY: &str = "__ADMIN_MULTISIG__";
pub const ACTIVE_VALIDATOR_SET_KEY: &str = "__ACTIVE_VALIDATOR_SET__";
/// G7: epoch'a özel küme anlık görüntüsü (`evidence_max_age_epochs` boyunca
/// index→pubkey korunur); `ACTIVE_VALIDATOR_SET_KEY`nin aksine üzerine yazılmaz.
pub fn active_validator_set_epoch_key(epoch: u64) -> String {
    format!("__ACTIVE_VALIDATOR_SET_EPOCH_{epoch}__")
}

/// G5/G6: son kesinleşmiş konsensüs ucu `bincode((SignedHeader, QuorumCertificate))`
/// — blok flush'ıyla AYNI atomik batch'te yazılır; restart'ta motor buradan
/// `last_qc`'yi alır (yoksa fail-closed: BFT modu başlamaz, G6 catch-up).
pub const CONSENSUS_TIP_KEY: &str = "__CONSENSUS_TIP__";

/// `ApproveValidator`/`RemoveValidator` `receiver` sentinel adresi; hedef
/// PAYLOAD'da. 0x…08, `SLASH_VALIDATOR_ADDRESS` (0x…07) ile aynı desen, ayrı adres.
pub const VALIDATOR_ADMIN_ADDRESS: &str = "0x0000000000000000000000000000000000000008";

/// Admin multisig aksiyon imzalarının domain etiketi (§2.1). Hesap
/// (secp256k1) anahtarlarıyla imzalanır; konsensüs oyu DEĞİLDİR.
pub const DOMAIN_ADMIN_ACTION: &[u8] = b"ZAGROS/ADMIN-ACTION/v1";

/// Liveness/uptime sayaçları (§11.4). `participated/total` o epoch'ta
/// imzaladığı (Probation: gölge) QC oranı; `strikes` ardışık eşik-altı epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LivenessCounters {
    pub epoch: u64,
    pub participated: u64,
    pub total: u64,
    pub strikes: u32,
}

impl LivenessCounters {
    /// Katılım oranı (bps). `total == 0` → `None` (ölçüm yok; fail-closed:
    /// "geçti" sayılmaz).
    pub fn participation_bps(&self) -> Option<u16> {
        if self.total == 0 {
            None
        } else {
            Some(((self.participated as u128 * 10_000) / self.total as u128).min(10_000) as u16)
        }
    }
}

/// `RegisterValidator` payload'ı (bincode). Eski 2 baytlık komisyon payload'ı
/// ARTIK KABUL EDİLMEZ (fail-closed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterValidatorPayload {
    pub consensus_pubkey: [u8; 32],
    /// `zagros_crypto::prove_key_ownership(kp, domain, account_address, None)`
    pub ownership_proof: Vec<u8>,
    pub declaration: ValidatorDeclaration,
}

impl RegisterValidatorPayload {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let p: Self = bincode::deserialize(bytes).map_err(|e| {
            ZagrosError::Other(format!("RegisterValidator payload cozulemedi: {e}"))
        })?;
        if p.consensus_pubkey == [0u8; 32] {
            return Err(ZagrosError::Other("consensus_pubkey sifir olamaz".into()));
        }
        if p.ownership_proof.len() != 64 {
            return Err(ZagrosError::Other("ownership_proof 64 bayt olmali".into()));
        }
        if p.declaration.provider.is_empty()
            || p.declaration.region.is_empty()
            || p.declaration.operator_id == [0u8; 32]
        {
            return Err(ZagrosError::Other(
                "beyan eksik (provider/region/operator_id)".into(),
            ));
        }
        if p.declaration.provider.len() > 64 || p.declaration.region.len() > 64 {
            return Err(ZagrosError::Other("beyan alanlari cok uzun".into()));
        }
        Ok(p)
    }
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("RegisterValidatorPayload serilestirilebilir")
    }
}

/// §15 (G14): `RotateConsensusKey` payload'ı; kanıt yeni anahtarın imzası, eski
/// pubkey zincirden okunur. Sonraki epoch'ta etkin (INV-K1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateConsensusKeyPayload {
    pub new_pubkey: [u8; 32],
    /// `zagros_crypto::prove_key_ownership(yeni_kp, domain, hesap, Some(&eski_pubkey))`
    pub ownership_proof: Vec<u8>,
}

impl RotateConsensusKeyPayload {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let p: Self = bincode::deserialize(bytes).map_err(|e| {
            ZagrosError::Other(format!("RotateConsensusKey payload cozulemedi: {e}"))
        })?;
        if p.new_pubkey == [0u8; 32] {
            return Err(ZagrosError::Other("new_pubkey sifir olamaz".into()));
        }
        if p.ownership_proof.len() != 64 {
            return Err(ZagrosError::Other("ownership_proof 64 bayt olmali".into()));
        }
        Ok(p)
    }
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("RotateConsensusKeyPayload serilestirilebilir")
    }
}

/// §15 (G14): epoch sınırını bekleyen anahtar rotasyonu, `__KEYROT_<addr>__`
/// sentinel hesabının `contract_code` alanında bincode olarak durur.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingKeyRotation {
    pub new_pubkey: [u8; 32],
    /// Talebin verildiği epoch (bilgi amaçlı; uygulama "bir sonraki geçişte").
    pub requested_epoch: u64,
}

impl PendingKeyRotation {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| ZagrosError::Other(format!("PendingKeyRotation cozulemedi: {e}")))
    }
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("PendingKeyRotation serilestirilebilir")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AdminAction {
    Approve = 1,
    Remove = 2,
    /// G12: Faz A multisig vetosu, yalnız CONSENSUS kanalı tipli önerileri.
    /// `target` = "0x"+hex(proposal_id).
    VetoProposal = 3,
}

/// Faz A admin multisig aksiyonu (§2.1): secp256k1 imzalar, eşik kadar farklı
/// imzacı; `epoch` digest'te (başka epoch'ta replay yok).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminActionPayload {
    pub action: AdminAction,
    pub target: Address,
    pub epoch: u64,
    pub signatures: Vec<Vec<u8>>,
}

impl AdminActionPayload {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let p: Self = bincode::deserialize(bytes)
            .map_err(|e| ZagrosError::Other(format!("AdminAction payload cozulemedi: {e}")))?;
        if p.signatures.is_empty() || p.signatures.len() > 16 {
            return Err(ZagrosError::Other(
                "AdminAction imza sayisi [1,16] olmali".into(),
            ));
        }
        if !crate::Transaction::validate_address(&p.target) {
            return Err(ZagrosError::InvalidAddress);
        }
        Ok(p)
    }
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("AdminActionPayload serilestirilebilir")
    }
}

/// `keccak(DOMAIN_ADMIN_ACTION ‖ chain_id ‖ genesis_hash ‖ epoch ‖ 0 ‖ 0 ‖ action ‖ keccak(target_lowercase))`
pub fn admin_action_digest(
    domain: &ConsensusDomain,
    action: AdminAction,
    target: &str,
    epoch: u64,
) -> Hash {
    let target_hash = keccak256(target.to_ascii_lowercase().as_bytes());
    signing_digest(
        DOMAIN_ADMIN_ACTION,
        domain,
        epoch,
        0,
        0,
        action as u8,
        &target_hash,
    )
}

/// Genesis'te yazılan admin multisig (3-of-5). Faz A süresince küme
/// onay/çıkarma yetkisi; konsensüs oyu değildir (§2.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminMultisig {
    pub signers: Vec<Address>,
    pub threshold: u8,
}

impl AdminMultisig {
    pub fn validate(&self) -> Result<()> {
        if self.signers.is_empty() || self.signers.len() > 16 {
            return Err(ZagrosError::ConfigError(
                "admin multisig imzaci sayisi [1,16]".into(),
            ));
        }
        if self.threshold == 0 || self.threshold as usize > self.signers.len() {
            return Err(ZagrosError::ConfigError(
                "admin multisig esigi [1, imzaci sayisi]".into(),
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for a in &self.signers {
            if !crate::Transaction::validate_address(a) {
                return Err(ZagrosError::InvalidAddress);
            }
            if !seen.insert(a.to_ascii_lowercase()) {
                return Err(ZagrosError::ConfigError(
                    "admin multisig tekrar eden imzaci".into(),
                ));
            }
        }
        Ok(())
    }
    pub fn is_signer(&self, address: &str) -> bool {
        let a = address.to_ascii_lowercase();
        self.signers.iter().any(|s| s.to_ascii_lowercase() == a)
    }
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("AdminMultisig serilestirilebilir")
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let m: Self = bincode::deserialize(bytes)
            .map_err(|e| ZagrosError::ConfigError(format!("AdminMultisig cozulemedi: {e}")))?;
        m.validate()?;
        Ok(m)
    }
}

/// `ApproveValidator`/`RemoveValidator` işleminin gerçek hedefi, TEK doğruluk
/// kaynağı (scheduler çakışma kilidi + executor, `slash_target_address`
/// deseniyle aynı). Payload çözülemezse `None` (çağıran fail-closed reddeder).
pub fn validator_action_target(tx_type: &crate::TxType, payload: &[u8]) -> Option<Address> {
    match tx_type {
        crate::TxType::ApproveValidator | crate::TxType::RemoveValidator => {
            AdminActionPayload::decode(payload)
                .ok()
                .map(|p| p.target.to_ascii_lowercase())
        }
        _ => None,
    }
}

// CHAIN PARAMS (§0, §14), zincir-üstü, governance ile değişir, hard-code YOK

/// State'teki sentinel hesap anahtarı (`contract_code` = bincode(ChainParams)).
pub const CHAIN_PARAMS_KEY: &str = "__CHAIN_PARAMS__";

/// 🛡️ Köprü yetkili kümesi zincir üstünde: config'ten gelse ayrışan config'ler
/// kökü çatallar ve açık anahtar olmadan imzalar yalnız sayılırdı.
pub const BRIDGE_AUTHORITY_SET_KEY: &str = "__BRIDGE_AUTHORITY_SET__";

/// §23 (G10): planlı yükseltme kaydı (`__SCHEDULED_UPGRADE__`); governance
/// üretir, aktivasyon makinesi genesis binary'sinde hazır.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledUpgrade {
    pub target_ruleset: u32,
    /// Resmi sürüm dosyasının sha256'sı, güncelleme yardımcısı indirdiği
    /// binary'yi ZİNCİRDEKİ bu değere karşı doğrular (AS-U1).
    pub binary_sha256: [u8; 32],
    pub activation_epoch: u64,
}

/// §23: `ScheduledUpgrade`'in saklandığı sentinel anahtar.
pub const SCHEDULED_UPGRADE_KEY: &str = "__SCHEDULED_UPGRADE__";

/// ⏱️ QC kapanış toleransı: Q precommit'te hemen kapatmaz, N oy ya da `qc_grace_ms`
/// (geç oylar katılımı düşürüyordu). Ayrı sentinel; `ParamKey::QcGraceMs`.
pub const QC_GRACE_MS_KEY: &str = "__QC_GRACE_MS__";
pub const DEFAULT_QC_GRACE_MS: u64 = 200;

/// Üst sınır = `t_vote(r0) / 2` = `t_base / 4` (t_vote = t_base/2). Tur/oy
/// zaman aşımı yönetişimle küçülse bile grace bunun içinde kalır; ayrıca
/// motor çalışma anında precommit deadline'ını asla geçmez (ikinci kilit).
pub fn qc_grace_cap_ms(t_base_ms: u64) -> u64 {
    t_base_ms / 4
}

/// Grace'in yürürlükteki zamanlamaya sığdığını doğrular (INV: grace ≤ t_base/4).
pub fn validate_qc_grace(t_base_ms: u64, grace_ms: u64) -> Result<()> {
    if grace_ms > qc_grace_cap_ms(t_base_ms) {
        return Err(ZagrosError::ConfigError(format!(
            "qc_grace_ms {} > t_base_ms/4 = {} (tur zaman butcesine sigmali)",
            grace_ms,
            qc_grace_cap_ms(t_base_ms)
        )));
    }
    Ok(())
}

/// Sentinel kodlaması (u64 LE, 8 bayt; bozuksa `None` → varsayılan DEĞİL, hata).
pub fn decode_qc_grace(bytes: &[u8]) -> Result<u64> {
    let arr: [u8; 8] = bytes
        .try_into()
        .map_err(|_| ZagrosError::ConfigError("qc_grace_ms sentinel 8 bayt olmali".into()))?;
    Ok(u64::from_le_bytes(arr))
}
pub fn encode_qc_grace(ms: u64) -> Vec<u8> {
    ms.to_le_bytes().to_vec()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainParams {
    // --- consensus kanalı ---
    /// §23: yürürlükteki kural seti; YALNIZ epoch sınırında planlı yükseltme
    /// (ScheduledUpgrade, ≥%80 hazırlık) ile değişir (INV-U1), governance yolundan değil.
    pub active_ruleset: u32,
    pub max_validators: u16,
    pub max_block_bytes: u64,
    pub block_interval_ms: u64,
    pub t_base_ms: u64,
    pub epoch_seconds: u64,
    pub probation_epochs: u32,
    pub uptime_threshold_bps: u16,
    pub max_liveness_strikes: u32,
    pub idle_block_interval_s: u64,
    pub max_clock_skew_ms: u64,
    pub evidence_max_age_epochs: u32,
    pub bond_lock_seconds: u64,
    pub max_per_provider: u16,
    pub max_per_region: u16,
    pub max_per_operator: u16,
    pub timelock_epochs: u32,
    /// G12: tipli önerilerin oylama penceresi (epoch cinsinden, node-yerel
    /// saniye config'i yerine ZİNCİRDE, determinizm için). Varsayılan 168
    /// (1 saatlik epoch'ta 1 hafta).
    pub gov_voting_epochs: u32,
    // --- economic kanalı ---
    /// 18 ondalıklı ham ZERENYA (1 ZERENYA = 1 troy ons).
    pub min_validator_stake_zerenya: u128,
    pub stake_hysteresis_bps: u16,
    pub application_fee_zerenya: u128,
    /// 🚨 REZERVE, HİÇBİR YERDEN OKUNMUYOR: genesis'te 0, tüketen kod yok; yine
    /// de governance'tan oylanabilir, oylama geçer ve hiçbir şey olmaz. Rezerv
    /// mekanizması uygulanana kadar yer tutucu.
    pub reserve_floor_zerenya_per_day: u128,
    pub reserve_end_epoch: u64,
    pub reporter_reward_cap_bps: u16,
    /// 🚨 REZERVE, okunmuyor: beyan doğrulanamadığından ceza uygulanamaz;
    /// etkinleştirmek için önce beyan doğrulaması gerekir.
    pub false_declaration_slash_bps: u16,
    pub vote_cap_bps: u16,
    pub staker_quorum_bps: u16,
}

impl ChainParams {
    /// CONSENSUS-SPEC v0.2 §0/§13/§14 başlangıç değerleri (genesis'e yazılır).
    pub fn genesis_defaults() -> Self {
        const ZERENYA: u128 = 1_000_000_000_000_000_000;
        Self {
            active_ruleset: 1,
            // Kapasite 10: sert üst sınır, hatalı/ele geçirilmiş admin onayı bile
            // 11. üyeyi ekleyemesin. Büyütmek ParamChange governance'ı ile (kod tavanı 101).
            max_validators: 10,
            max_block_bytes: 262_144,
            block_interval_ms: 500,
            t_base_ms: 1_500,
            epoch_seconds: 7_200,
            probation_epochs: 3,
            uptime_threshold_bps: 9_000,
            max_liveness_strikes: 3,
            idle_block_interval_s: 600,
            max_clock_skew_ms: 2_000,
            // 24 epoch = 24 saat: kanıt bildirimi otomatik değil (insan gönderir);
            // 2 epoch'ta gece yapılan çift imza sabaha zaman aşımına uğrardı.
            // INV-E3: bond_lock 7 gün → tavan 167 epoch, rahat karşılar.
            evidence_max_age_epochs: 24,
            bond_lock_seconds: 604_800,
            max_per_provider: 5,
            max_per_region: 7,
            max_per_operator: 1,
            timelock_epochs: 3,
            gov_voting_epochs: 168,
            min_validator_stake_zerenya: ZERENYA * 17 / 100, // 0,17 ons
            stake_hysteresis_bps: 2_000,
            application_fee_zerenya: ZERENYA * 5 / 1_000, // 0,005 ons
            reserve_floor_zerenya_per_day: 0,             // İNSAN-KARARI-1: genesis'te doldurulur
            reserve_end_epoch: 0,
            reporter_reward_cap_bps: 5_000,
            false_declaration_slash_bps: 1_000,
            vote_cap_bps: 1_000,
            staker_quorum_bps: 2_000,
        }
    }

    /// Sınır doğrulama (INV-G3). Governance'tan gelen hiçbir değer bu kuralları
    /// geçemez; özellikle INV-E3: `bond_lock ≥ evidence_max_age × epoch`.
    pub fn validate(&self) -> Result<()> {
        let err = |m: &str| Err(ZagrosError::ConfigError(m.to_string()));
        if !(1..=720).contains(&self.gov_voting_epochs) {
            return err("gov_voting_epochs [1, 720] araliginda olmali");
        }
        if self.active_ruleset == 0 {
            return err("active_ruleset 0 olamaz (kural setleri 1'den baslar)");
        }
        if self.max_validators < MIN_VALIDATORS || self.max_validators > MAX_VALIDATORS_HARD {
            return err("max_validators [4, 101] araliginda olmali");
        }
        if !(16 * 1024..=8 * 1024 * 1024).contains(&self.max_block_bytes) {
            return err("max_block_bytes [16 KiB, 8 MiB] araliginda olmali");
        }
        if !(100..=60_000).contains(&self.block_interval_ms) {
            return err("block_interval_ms [100, 60000] araliginda olmali");
        }
        if self.t_base_ms < self.block_interval_ms || self.t_base_ms > 120_000 {
            return err("t_base_ms block_interval_ms'den kucuk olamaz, 120 s'yi asamaz");
        }
        if !(300..=86_400).contains(&self.epoch_seconds) {
            return err("epoch_seconds [300, 86400] araliginda olmali");
        }
        if self.probation_epochs == 0 || self.probation_epochs > 100 {
            return err("probation_epochs [1, 100] araliginda olmali");
        }
        if self.uptime_threshold_bps > 10_000 || self.uptime_threshold_bps < 5_000 {
            return err("uptime_threshold_bps [5000, 10000] araliginda olmali");
        }
        if self.max_liveness_strikes == 0 {
            return err("max_liveness_strikes >= 1 olmali");
        }
        if self.idle_block_interval_s < 10 {
            return err("idle_block_interval_s >= 10 olmali");
        }
        if self.max_clock_skew_ms > 60_000 {
            return err("max_clock_skew_ms <= 60 s olmali");
        }
        if self.evidence_max_age_epochs == 0 {
            return err("evidence_max_age_epochs >= 1 olmali");
        }
        // INV-E3 off-by-one: kanıt E+max_age epoch'unun SONUNA kadar kabul edilir,
        // bond kilidi unstake anından max_age×epoch sürer; epoch başında unstake
        // bir epoch'luk boşluk bırakırdı. +1 epoch güvenlik payı.
        let min_bond_lock = (self.evidence_max_age_epochs as u64)
            .saturating_add(1)
            .saturating_mul(self.epoch_seconds);
        if self.bond_lock_seconds < min_bond_lock {
            return err(
                "bond_lock_seconds >= (evidence_max_age_epochs + 1) * epoch_seconds olmali (INV-E3)",
            );
        }
        if self.max_per_operator == 0 || self.max_per_provider == 0 || self.max_per_region == 0 {
            return err("cesitlilik tavanlari >= 1 olmali");
        }
        if self.timelock_epochs == 0 {
            return err("timelock_epochs >= 1 olmali");
        }
        if self.min_validator_stake_zerenya == 0 {
            return err("min_validator_stake_zerenya > 0 olmali");
        }
        for (name, v) in [
            ("stake_hysteresis_bps", self.stake_hysteresis_bps),
            ("reporter_reward_cap_bps", self.reporter_reward_cap_bps),
            (
                "false_declaration_slash_bps",
                self.false_declaration_slash_bps,
            ),
            ("vote_cap_bps", self.vote_cap_bps),
            ("staker_quorum_bps", self.staker_quorum_bps),
        ] {
            if v > 10_000 {
                return err(&format!("{name} <= 10000 olmali"));
            }
        }
        if self.vote_cap_bps == 0 || self.staker_quorum_bps == 0 {
            return err("vote_cap_bps ve staker_quorum_bps > 0 olmali");
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("ChainParams serilestirilebilir")
    }

    /// Eksik/bozuk veri → `Err` (fail-closed; varsayılana DÜŞMEZ).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let p: Self = bincode::deserialize(bytes)
            .map_err(|e| ZagrosError::ConfigError(format!("ChainParams cozulemedi: {e}")))?;
        p.validate()?;
        Ok(p)
    }
}

// TESTLER
#[cfg(test)]
mod tests {
    /// 🗳️ dApp/TS kodlayıcısı için REFERANS VEKTÖRLER (bayt-bayt uyum;
    /// `zagros-dapp/lib/governance.test.ts` bu hex'leri doğrular).
    #[test]
    fn gov_payload_reference_vectors_for_dapp() {
        use super::ParamKey::*;
        let v1 = ProposalAction::ParamChange(vec![ParamUpdate {
            key: MaxValidators,
            value: 21,
        }])
        .encode_payload()
        .unwrap();
        let v2 = ProposalAction::ParamChange(vec![
            ParamUpdate {
                key: VoteCapBps,
                value: 900,
            },
            ParamUpdate {
                key: StakerQuorumBps,
                value: 2_500,
            },
        ])
        .encode_payload()
        .unwrap();
        let v3 = ProposalAction::ScheduleUpgrade {
            target_ruleset: 2,
            binary_sha256: [0x11; 32],
            activation_epoch: 500,
        }
        .encode_payload()
        .unwrap();
        let v4 = ProposalAction::ShortenAdminAuthority {
            end_timestamp: 1_800_000_000,
        }
        .encode_payload()
        .unwrap();
        let v5 = ProposalAction::ParamChange(vec![ParamUpdate {
            key: QcGraceMs,
            value: 250,
        }])
        .encode_payload()
        .unwrap();
        assert_eq!(
            hex::encode(&v1),
            "5a474f5631000100000001000000000000000000000015000000000000000000000000000000"
        );
        assert_eq!(hex::encode(&v2), "5a474f563100010000000200000000000000180000008403000000000000000000000000000019000000c4090000000000000000000000000000");
        assert_eq!(hex::encode(&v3), "5a474f56310002000000020000001111111111111111111111111111111111111111111111111111111111111111f401000000000000");
        assert_eq!(hex::encode(&v4), "5a474f5631000300000000d2496b00000000");
        assert_eq!(
            hex::encode(&v5),
            "5a474f5631000100000001000000000000001a000000fa000000000000000000000000000000"
        );
        assert_eq!(
            ProposalAction::decode_payload(&v1).unwrap().unwrap(),
            ProposalAction::ParamChange(vec![ParamUpdate {
                key: MaxValidators,
                value: 21
            }])
        );
    }

    use super::*;

    fn domain() -> ConsensusDomain {
        ConsensusDomain::new(21072026, [7u8; 32])
    }

    fn set(n: u16) -> ActiveValidatorSet {
        ActiveValidatorSet {
            epoch: 3,
            members: (0..n)
                .map(|i| ValidatorMember {
                    address: format!("0x{:040x}", i + 1),
                    consensus_pubkey: [i as u8 + 1; 32],
                })
                .collect(),
        }
    }

    // ---- §3 quorum matematiği (TC-S1) ----
    #[test]
    fn quorum_table_matches_spec() {
        for (n, f, q) in [
            (4, 1, 3),
            (5, 1, 4),
            (7, 2, 5),
            (10, 3, 7),
            (13, 4, 9),
            (16, 5, 11),
            (21, 6, 15),
            (31, 10, 21),
            (51, 16, 35),
            (101, 33, 68),
        ] {
            assert_eq!(byzantine_tolerance(n), f, "f(N={n})");
            assert_eq!(quorum_of(n).unwrap(), q, "Q(N={n})");
        }
    }

    /// INV-C2'nin cebirsel temeli: her N için iki quorum en az f+1 node'da
    /// kesişir (2Q − N ≥ f + 1) — yani en az bir dürüst node.
    #[test]
    fn two_quorums_always_intersect_in_an_honest_node() {
        for n in MIN_VALIDATORS..=MAX_VALIDATORS_HARD {
            let q = quorum_of(n).unwrap() as i32;
            let f = byzantine_tolerance(n) as i32;
            assert!(
                2 * q - (n as i32) > f,
                "N={n}: 2Q-N={} <= f={}",
                2 * q - n as i32,
                f
            );
            assert!(
                q <= n as i32 - f,
                "N={n}: Q={q} > N-f={} (f offline ile liveness imkansiz)",
                n as i32 - f
            );
        }
    }

    #[test]
    fn quorum_fails_closed_outside_bounds() {
        assert!(quorum_of(3).is_err(), "N<4 BFT anlamsiz (INV-S1)");
        assert!(quorum_of(0).is_err());
        assert!(quorum_of(102).is_err(), "kod tavani");
    }

    // ---- validator set hash deterministik, sıradan bağımsız (INV-S2) ----
    #[test]
    fn validator_set_hash_is_order_independent_and_epoch_bound() {
        let a = set(5);
        let mut b = a.clone();
        b.members.reverse();
        assert_eq!(a.hash(), b.hash());
        let mut c = a.clone();
        c.epoch += 1;
        assert_ne!(a.hash(), c.hash());
        let mut d = a.clone();
        d.members[0].consensus_pubkey[0] ^= 1;
        assert_ne!(a.hash(), d.hash());
    }

    #[test]
    fn validator_set_rejects_duplicates_and_zero_keys() {
        let mut s = set(5);
        s.members[1].consensus_pubkey = s.members[0].consensus_pubkey;
        assert!(s.validate().is_err());
        let mut s = set(5);
        s.members[1].address = s.members[0].address.to_uppercase();
        assert!(
            s.validate().is_err(),
            "adres karsilastirmasi buyuk/kucuk harf duyarsiz"
        );
        let mut s = set(5);
        s.members[2].consensus_pubkey = [0u8; 32];
        assert!(s.validate().is_err());
        assert!(set(5).validate().is_ok());
    }

    // ---- §6 domain separation (TC-D1) ----
    #[test]
    fn signing_digest_changes_with_every_field() {
        let d = domain();
        let base = signing_digest(DOMAIN_VOTE, &d, 1, 10, 0, 1, &[9u8; 32]);
        assert_ne!(
            base,
            signing_digest(DOMAIN_SHADOW, &d, 1, 10, 0, 1, &[9u8; 32]),
            "tag"
        );
        assert_ne!(
            base,
            signing_digest(DOMAIN_HEADER, &d, 1, 10, 0, 1, &[9u8; 32]),
            "tag"
        );
        assert_ne!(
            base,
            signing_digest(
                DOMAIN_VOTE,
                &ConsensusDomain::new(1, [7u8; 32]),
                1,
                10,
                0,
                1,
                &[9u8; 32]
            ),
            "chain_id"
        );
        assert_ne!(
            base,
            signing_digest(
                DOMAIN_VOTE,
                &ConsensusDomain::new(21072026, [8u8; 32]),
                1,
                10,
                0,
                1,
                &[9u8; 32]
            ),
            "genesis_hash"
        );
        assert_ne!(
            base,
            signing_digest(DOMAIN_VOTE, &d, 2, 10, 0, 1, &[9u8; 32]),
            "epoch"
        );
        assert_ne!(
            base,
            signing_digest(DOMAIN_VOTE, &d, 1, 11, 0, 1, &[9u8; 32]),
            "height"
        );
        assert_ne!(
            base,
            signing_digest(DOMAIN_VOTE, &d, 1, 10, 1, 1, &[9u8; 32]),
            "round"
        );
        assert_ne!(
            base,
            signing_digest(DOMAIN_VOTE, &d, 1, 10, 0, 2, &[9u8; 32]),
            "phase"
        );
        assert_ne!(
            base,
            signing_digest(DOMAIN_VOTE, &d, 1, 10, 0, 1, &[10u8; 32]),
            "block_hash"
        );
        // deterministik
        assert_eq!(
            base,
            signing_digest(DOMAIN_VOTE, &d, 1, 10, 0, 1, &[9u8; 32])
        );
    }

    #[test]
    fn signing_payload_is_fixed_width_and_unambiguous() {
        let d = domain();
        let p = signing_payload(DOMAIN_VOTE, &d, 1, 2, 3, 1, &[0u8; 32]);
        assert_eq!(p.len(), DOMAIN_VOTE.len() + 8 + 32 + 8 + 8 + 4 + 1 + 32);
        assert!(p.starts_with(DOMAIN_VOTE));
    }

    #[test]
    fn shadow_vote_uses_shadow_domain() {
        let mut v = Vote {
            height: 5,
            round: 0,
            phase: VotePhase::Prevote,
            block_hash: [1u8; 32],
            validator_idx: 0,
            shadow: false,
            sig: vec![],
        };
        let real = v.signing_digest(&domain(), 1);
        v.shadow = true;
        assert_ne!(
            real,
            v.signing_digest(&domain(), 1),
            "golge oy gercek oyun digest'ini uretemez (INV-L4)"
        );
    }

    // ---- §23 (G10) yükseltme tipleri ----
    #[test]
    fn g10_chain_params_rejects_zero_ruleset_and_header_rejects_stale_declaration() {
        let mut p = ChainParams::genesis_defaults();
        p.active_ruleset = 0;
        assert!(p.validate().is_err(), "active_ruleset=0 gecmemeli");

        let mut p2 = ChainParams::genesis_defaults();
        p2.active_ruleset = 2;
        let mut h = header(1, [0u8; 32], None);
        h.epoch = 0;
        h.max_ruleset = 1; // eski yazılım beyanı — yeni kurallar altında blok üretemez
        assert!(
            h.validate_structure(&p2).is_err(),
            "max_ruleset < active reddedilmeli"
        );
        h.max_ruleset = 2;
        h.body_bytes = 100;
        assert!(
            h.validate_structure(&p2).is_ok(),
            "esit beyan gecmeli: {:?}",
            h.validate_structure(&p2)
        );
    }

    // ---- §5 header ----
    fn header(n: u64, parent: Hash, last_qc: Option<QuorumCertificate>) -> BlockHeaderV2 {
        BlockHeaderV2 {
            version: BlockHeaderV2::VERSION,
            number: n,
            parent_hash: parent,
            state_root: [3u8; 32],
            timestamp_ms: 1_700_000_000_000,
            tx_root: BlockHeaderV2::compute_tx_root(&[]),
            tx_count: 0,
            body_bytes: 100,
            epoch: 3,
            validator_set_hash: set(5).hash(),
            round: 0,
            proposer_idx: 1,
            max_ruleset: 1,
            last_qc,
        }
    }

    fn qc_for(h: &BlockHeaderV2, s: &ActiveValidatorSet, signers: &[u16]) -> QuorumCertificate {
        let mut bits = vec![0u8; QuorumCertificate::bitset_len_for(s.len())];
        for i in signers {
            QuorumCertificate::set_signer(&mut bits, *i);
        }
        QuorumCertificate {
            height: h.number,
            round: h.round,
            block_hash: h.hash(),
            epoch: s.epoch,
            validator_set_hash: s.hash(),
            signers: bits,
            sigs: signers.iter().map(|_| vec![0u8; 64]).collect(),
        }
    }

    #[test]
    fn header_hash_is_keccak_of_bincode_and_changes_with_content() {
        let h = header(1, [0u8; 32], None);
        assert_eq!(h.hash(), keccak256(&bincode::serialize(&h).unwrap()));
        let mut h2 = h.clone();
        h2.state_root[0] ^= 1;
        assert_ne!(h.hash(), h2.hash());
        let d = domain();
        assert_ne!(h.signing_digest(&d), h2.signing_digest(&d));
    }

    #[test]
    fn header_structure_rules() {
        let p = ChainParams::genesis_defaults();
        let g = header(1, [0u8; 32], None);
        assert!(
            g.validate_structure(&p).is_ok(),
            "blok 1 last_qc'siz olabilir"
        );
        let s = set(5);
        let qc = qc_for(&g, &s, &[0, 1, 2, 3]);
        let h2 = header(2, g.hash(), Some(qc.clone()));
        assert!(h2.validate_structure(&p).is_ok());
        let mut bad = h2.clone();
        bad.last_qc = None;
        assert!(
            bad.validate_structure(&p).is_err(),
            "blok 2 last_qc tasimali"
        );
        let mut bad = h2.clone();
        bad.parent_hash[0] ^= 1;
        assert!(
            bad.validate_structure(&p).is_err(),
            "last_qc.block_hash != parent"
        );
        let mut bad = h2.clone();
        bad.body_bytes = (p.max_block_bytes + 1) as u32;
        assert!(bad.validate_structure(&p).is_err(), "byte tavani");
        let mut bad = h2.clone();
        bad.version = 1;
        assert!(bad.validate_structure(&p).is_err(), "surum");
        let mut bad = h2;
        bad.number = 0;
        assert!(bad.validate_structure(&p).is_err());
    }

    // ---- §5 QC yapısal (TC-Q1) ----
    #[test]
    fn qc_structure_rules() {
        let s = set(5); // Q = 4
        let h = header(1, [0u8; 32], None);
        assert!(qc_for(&h, &s, &[0, 1, 2, 3]).validate_structure(&s).is_ok());
        assert!(qc_for(&h, &s, &[0, 1, 2, 3, 4])
            .validate_structure(&s)
            .is_ok());
        assert!(
            qc_for(&h, &s, &[0, 1, 2]).validate_structure(&s).is_err(),
            "1 eksik imza"
        );
        let mut qc = qc_for(&h, &s, &[0, 1, 2, 3]);
        qc.sigs.pop();
        assert!(
            qc.validate_structure(&s).is_err(),
            "bitset/sig sayisi uyusmazligi"
        );
        let mut qc = qc_for(&h, &s, &[0, 1, 2, 3]);
        qc.epoch += 1;
        assert!(qc.validate_structure(&s).is_err(), "yanlis epoch");
        let mut qc = qc_for(&h, &s, &[0, 1, 2, 3]);
        qc.validator_set_hash[0] ^= 1;
        assert!(qc.validate_structure(&s).is_err(), "kume hash");
        let mut qc = qc_for(&h, &s, &[0, 1, 2, 3]);
        qc.block_hash = NIL_HASH;
        assert!(qc.validate_structure(&s).is_err(), "nil QC olamaz");
        let mut qc = qc_for(&h, &s, &[0, 1, 2, 3]);
        qc.signers = vec![0u8; 3];
        assert!(qc.validate_structure(&s).is_err(), "bitset boyutu");
        let mut qc = qc_for(&h, &s, &[0, 1, 2, 3]);
        QuorumCertificate::set_signer(&mut qc.signers, 7); // kume disi indeks (N=5)
        qc.sigs.push(vec![0u8; 64]);
        assert!(qc.validate_structure(&s).is_err(), "indeks kume disinda");
    }

    #[test]
    fn qc_signer_bitset_roundtrip() {
        let mut bits = vec![0u8; QuorumCertificate::bitset_len_for(21)];
        for i in [0u16, 7, 8, 15, 20] {
            QuorumCertificate::set_signer(&mut bits, i);
        }
        let qc = QuorumCertificate {
            height: 1,
            round: 0,
            block_hash: [1u8; 32],
            epoch: 0,
            validator_set_hash: [0u8; 32],
            signers: bits,
            sigs: vec![],
        };
        assert_eq!(qc.signer_indices(), vec![0, 7, 8, 15, 20]);
    }

    // ---- §11 evidence yapısal ----
    #[test]
    fn double_vote_evidence_structure() {
        let v = |hash: u8, sig: u8| Vote {
            height: 9,
            round: 1,
            phase: VotePhase::Precommit,
            block_hash: [hash; 32],
            validator_idx: 4,
            shadow: false,
            sig: vec![sig; 64],
        };
        assert!(Evidence::DoubleVote {
            a: v(1, 1),
            b: v(2, 2)
        }
        .validate_structure()
        .is_ok());
        assert!(
            Evidence::DoubleVote {
                a: v(1, 1),
                b: v(1, 2)
            }
            .validate_structure()
            .is_err(),
            "ayni hash"
        );
        let mut b = v(2, 2);
        b.round = 2;
        assert!(
            Evidence::DoubleVote { a: v(1, 1), b }
                .validate_structure()
                .is_err(),
            "farkli round"
        );
        let mut b = v(2, 2);
        b.validator_idx = 5;
        assert!(
            Evidence::DoubleVote { a: v(1, 1), b }
                .validate_structure()
                .is_err(),
            "farkli validator"
        );
        let mut b = v(2, 2);
        b.phase = VotePhase::Prevote;
        assert!(
            Evidence::DoubleVote { a: v(1, 1), b }
                .validate_structure()
                .is_err(),
            "farkli phase"
        );
    }

    #[test]
    fn double_propose_evidence_structure() {
        let a = Box::new(SignedHeader {
            header: header(4, [0u8; 32], None),
            sig: vec![1; 64],
        });
        let mut hb = header(4, [0u8; 32], None);
        hb.state_root = [9u8; 32];
        let b = Box::new(SignedHeader {
            header: hb,
            sig: vec![2; 64],
        });
        assert!(Evidence::DoublePropose {
            a: a.clone(),
            b: b.clone()
        }
        .validate_structure()
        .is_ok());
        assert!(
            Evidence::DoublePropose {
                a: a.clone(),
                b: a.clone()
            }
            .validate_structure()
            .is_err(),
            "ayni header"
        );
        let mut c = b.clone();
        c.header.proposer_idx = 2;
        assert!(
            Evidence::DoublePropose { a, b: c }
                .validate_structure()
                .is_err(),
            "farkli proposer"
        );
    }

    // ---- §14 ChainParams (INV-G3, INV-E3) ----
    #[test]
    fn genesis_defaults_match_spec_and_validate() {
        let p = ChainParams::genesis_defaults();
        assert!(p.validate().is_ok());
        // C-8 idi: genesis üst sınırı doğrudan sert tavana (101) yazılıyordu.
        // 🚨 Kullanıcı kararı: kapasite 10. Sert tavan (101)
        // DEĞİŞMEDİ, yalnız genesis'e yazılan başlangıç değeri düştü.
        assert_eq!(p.max_validators, 10);
        assert!(p.max_validators <= MAX_VALIDATORS_HARD);
        assert_eq!(p.max_block_bytes, 262_144);
        assert_eq!(p.block_interval_ms, 500);
        assert_eq!(p.t_base_ms, 1_500);
        assert_eq!(p.epoch_seconds, 7_200);
        assert_eq!(p.probation_epochs, 3);
        assert_eq!(p.uptime_threshold_bps, 9_000);
        assert_eq!(p.idle_block_interval_s, 600);
        assert_eq!(p.bond_lock_seconds, 604_800);
        assert_eq!(p.min_validator_stake_zerenya, 170_000_000_000_000_000);
        assert_eq!(p.application_fee_zerenya, 5_000_000_000_000_000);
        assert_eq!(p.vote_cap_bps, 1_000);
        assert_eq!(p.staker_quorum_bps, 2_000);
        assert_eq!(p.timelock_epochs, 3);
        // Genesis bilerek en eski kural setinde başlar; yükseltme yolu gerçek zincirde prova edilebilir.
        assert_eq!(p.active_ruleset, 1);
        assert!(
            p.active_ruleset <= SUPPORTED_RULESET,
            "binary, genesis kural setini desteklemeli"
        );
        assert_eq!(p.gov_voting_epochs, 168);
    }

    #[test]
    fn chain_params_bounds_fail_closed() {
        let base = ChainParams::genesis_defaults();
        let mut p = base.clone();
        p.max_validators = 3;
        assert!(p.validate().is_err());
        let mut p = base.clone();
        p.max_validators = 102;
        assert!(p.validate().is_err());
        let mut p = base.clone();
        p.bond_lock_seconds = p.evidence_max_age_epochs as u64 * p.epoch_seconds - 1;
        assert!(p.validate().is_err(), "INV-E3");
        let mut p = base.clone();
        p.t_base_ms = p.block_interval_ms - 1;
        assert!(p.validate().is_err());
        let mut p = base.clone();
        p.uptime_threshold_bps = 10_001;
        assert!(p.validate().is_err());
        let mut p = base.clone();
        p.vote_cap_bps = 0;
        assert!(p.validate().is_err());
        let mut p = base.clone();
        p.max_block_bytes = 1;
        assert!(p.validate().is_err());
        let mut p = base;
        p.min_validator_stake_zerenya = 0;
        assert!(p.validate().is_err());
    }

    #[test]
    fn chain_params_roundtrip_and_decode_fails_closed() {
        let p = ChainParams::genesis_defaults();
        let bytes = p.encode();
        assert_eq!(ChainParams::decode(&bytes).unwrap(), p);
        assert!(
            ChainParams::decode(&bytes[..bytes.len() - 3]).is_err(),
            "kesik veri"
        );
        assert!(
            ChainParams::decode(&[]).is_err(),
            "bos veri varsayilana DUSMEZ"
        );
        let mut bad = p.clone();
        bad.max_validators = 2;
        assert!(
            ChainParams::decode(&bad.encode()).is_err(),
            "kodlanmis ama gecersiz param reddedilir"
        );
    }

    #[test]
    fn liveness_participation_fails_closed_without_measurement() {
        assert_eq!(LivenessCounters::default().participation_bps(), None);
        assert_eq!(
            LivenessCounters {
                epoch: 1,
                participated: 9,
                total: 10,
                strikes: 0
            }
            .participation_bps(),
            Some(9_000)
        );
        assert_eq!(
            LivenessCounters {
                epoch: 1,
                participated: 10,
                total: 10,
                strikes: 0
            }
            .participation_bps(),
            Some(10_000)
        );
    }

    #[test]
    fn register_payload_decode_rules() {
        let good = RegisterValidatorPayload {
            consensus_pubkey: [1u8; 32],
            ownership_proof: vec![0u8; 64],
            declaration: ValidatorDeclaration {
                provider: "aws".into(),
                region: "eu-central-1".into(),
                asn: 16509,
                operator_id: [2u8; 32],
            },
        };
        assert_eq!(
            RegisterValidatorPayload::decode(&good.encode()).unwrap(),
            good
        );
        let mut b = good.clone();
        b.consensus_pubkey = [0u8; 32];
        assert!(RegisterValidatorPayload::decode(&b.encode()).is_err());
        let mut b = good.clone();
        b.ownership_proof = vec![0u8; 63];
        assert!(RegisterValidatorPayload::decode(&b.encode()).is_err());
        let mut b = good.clone();
        b.declaration.provider.clear();
        assert!(RegisterValidatorPayload::decode(&b.encode()).is_err());
        let mut b = good;
        b.declaration.operator_id = [0u8; 32];
        assert!(RegisterValidatorPayload::decode(&b.encode()).is_err());
        assert!(
            RegisterValidatorPayload::decode(&[0x00, 0xfa]).is_err(),
            "eski 2 baytlik komisyon payload'i reddedilir"
        );
        assert!(RegisterValidatorPayload::decode(&[]).is_err());
    }

    #[test]
    fn admin_action_payload_and_digest() {
        let target = "0x00000005668becb40d7eaafdae73ed6347932d49";
        let p = AdminActionPayload {
            action: AdminAction::Approve,
            target: target.into(),
            epoch: 4,
            signatures: vec![vec![0u8; 65]],
        };
        assert_eq!(AdminActionPayload::decode(&p.encode()).unwrap(), p);
        let mut b = p.clone();
        b.signatures.clear();
        assert!(AdminActionPayload::decode(&b.encode()).is_err());
        let mut b = p.clone();
        b.target = "kotu".into();
        assert!(AdminActionPayload::decode(&b.encode()).is_err());
        let d = domain();
        let base = admin_action_digest(&d, AdminAction::Approve, target, 4);
        assert_ne!(
            base,
            admin_action_digest(&d, AdminAction::Remove, target, 4),
            "aksiyon"
        );
        assert_ne!(
            base,
            admin_action_digest(&d, AdminAction::Approve, target, 5),
            "epoch (replay)"
        );
        assert_ne!(
            base,
            admin_action_digest(
                &d,
                AdminAction::Approve,
                "0x0000000000000000000000000000000000000001",
                4
            ),
            "hedef"
        );
        assert_ne!(
            base,
            admin_action_digest(
                &ConsensusDomain::new(1, [7u8; 32]),
                AdminAction::Approve,
                target,
                4
            ),
            "zincir"
        );
        assert_eq!(
            base,
            admin_action_digest(&d, AdminAction::Approve, &target.to_uppercase(), 4),
            "hedef adres buyuk/kucuk harf duyarsiz"
        );
        assert_eq!(
            validator_action_target(&crate::TxType::ApproveValidator, &p.encode()).as_deref(),
            Some(target)
        );
        assert_eq!(
            validator_action_target(&crate::TxType::Transfer, &p.encode()),
            None
        );
        assert_eq!(
            validator_action_target(&crate::TxType::RemoveValidator, &[1, 2, 3]),
            None
        );
    }

    /// 0x…08 (küme yönetimi) ile 0x…07 (slash) sentinel'leri ayrı adreslerdir ve
    /// hedef çözümleyiciler birbirinin işlem türünü tanımaz.
    #[test]
    fn validator_admin_sentinel_is_distinct_from_slash_sentinel() {
        assert_ne!(VALIDATOR_ADMIN_ADDRESS, crate::SLASH_VALIDATOR_ADDRESS);
        assert_ne!(VALIDATOR_ADMIN_ADDRESS, crate::VALIDATOR_REWARD_POOL);
        assert_ne!(VALIDATOR_ADMIN_ADDRESS, crate::LIQUIDITY_POOL_ADDRESS);
        assert_ne!(VALIDATOR_ADMIN_ADDRESS, crate::ZERENYA_TOKEN_ADDRESS);
        assert!(crate::Transaction::validate_address(
            VALIDATOR_ADMIN_ADDRESS
        ));
        let target = "0x00000005668becb40d7eaafdae73ed6347932d49";
        let p = AdminActionPayload {
            action: AdminAction::Remove,
            target: target.into(),
            epoch: 0,
            signatures: vec![vec![0u8; 65]],
        };
        // Slash çözümleyicisi admin payload'ını hedef olarak yorumlamaz (sentinel farklı);
        // admin çözümleyicisi SlashValidator türünü tanımaz.
        assert_eq!(
            crate::slash_target_address(VALIDATOR_ADMIN_ADDRESS, &p.encode()),
            VALIDATOR_ADMIN_ADDRESS
        );
        assert_eq!(
            validator_action_target(&crate::TxType::SlashValidator, &p.encode()),
            None
        );
        assert_eq!(
            validator_action_target(&crate::TxType::RemoveValidator, &p.encode()).as_deref(),
            Some(target)
        );
    }

    #[test]
    fn admin_multisig_rules() {
        let a = |i: u8| format!("0x{:040x}", i);
        let m = AdminMultisig {
            signers: vec![a(1), a(2), a(3), a(4), a(5)],
            threshold: 3,
        };
        assert!(m.validate().is_ok());
        assert!(m.is_signer(&a(3).to_uppercase()));
        assert!(!m.is_signer(&a(9)));
        assert_eq!(AdminMultisig::decode(&m.encode()).unwrap(), m);
        assert!(
            AdminMultisig {
                signers: vec![a(1), a(2)],
                threshold: 3
            }
            .validate()
            .is_err(),
            "esik > imzaci"
        );
        assert!(
            AdminMultisig {
                signers: vec![a(1), a(1)],
                threshold: 1
            }
            .validate()
            .is_err(),
            "tekrar"
        );
        assert!(AdminMultisig {
            signers: vec![],
            threshold: 1
        }
        .validate()
        .is_err());
        assert!(AdminMultisig {
            signers: vec![a(1)],
            threshold: 0
        }
        .validate()
        .is_err());
    }

    #[test]
    fn all_types_serialize_roundtrip() {
        let s = set(5);
        let h = header(1, [0u8; 32], None);
        let qc = qc_for(&h, &s, &[0, 1, 2, 3]);
        let sh = SignedHeader {
            header: header(2, h.hash(), Some(qc.clone())),
            sig: vec![1; 64],
        };
        let v = Vote {
            height: 2,
            round: 0,
            phase: VotePhase::Prevote,
            block_hash: h.hash(),
            validator_idx: 1,
            shadow: false,
            sig: vec![2; 64],
        };
        let hb = Heartbeat {
            height: 2,
            round: 0,
            timestamp_ms: 5,
            validator_idx: 1,
            sig: vec![3; 64],
        };
        let ev = Evidence::DoubleVote {
            a: v.clone(),
            b: Vote {
                block_hash: [5u8; 32],
                sig: vec![4; 64],
                ..v.clone()
            },
        };
        assert_eq!(
            bincode::deserialize::<SignedHeader>(&bincode::serialize(&sh).unwrap()).unwrap(),
            sh
        );
        assert_eq!(
            bincode::deserialize::<Vote>(&bincode::serialize(&v).unwrap()).unwrap(),
            v
        );
        assert_eq!(
            bincode::deserialize::<Heartbeat>(&bincode::serialize(&hb).unwrap()).unwrap(),
            hb
        );
        assert_eq!(
            bincode::deserialize::<Evidence>(&bincode::serialize(&ev).unwrap()).unwrap(),
            ev
        );
        assert_eq!(
            bincode::deserialize::<ActiveValidatorSet>(&bincode::serialize(&s).unwrap()).unwrap(),
            s
        );
    }
}

// G12, Governance iki kanal: tipli öneriler ve parametre yamaları (§14)

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovChannel {
    /// Aktif validatörler, eşit oy, ≥2/3 (ScheduleUpgrade: ≥%80).
    Consensus,
    /// Validator ≥2/3 VE staker çift-quorum (katılım ≥%20, >%50, adres tavanı).
    Economic,
}

/// Governance ile değiştirilebilir alanlar; ANAYASAL alanlar (42M, %80/%20,
/// chain_id, `active_ruleset` vb.) listede YOK (INV-G2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ParamKey {
    // --- consensus kanalı ---
    MaxValidators,
    MaxBlockBytes,
    BlockIntervalMs,
    TBaseMs,
    EpochSeconds,
    ProbationEpochs,
    UptimeThresholdBps,
    MaxLivenessStrikes,
    IdleBlockIntervalS,
    MaxClockSkewMs,
    EvidenceMaxAgeEpochs,
    BondLockSeconds,
    MaxPerProvider,
    MaxPerRegion,
    MaxPerOperator,
    TimelockEpochs,
    GovVotingEpochs,
    // --- economic kanalı ---
    MinValidatorStakeZerenya,
    StakeHysteresisBps,
    ApplicationFeeZerenya,
    ReserveFloorZerenyaPerDay,
    ReserveEndEpoch,
    ReporterRewardCapBps,
    FalseDeclarationSlashBps,
    VoteCapBps,
    StakerQuorumBps,
    // --- consensus kanalı (sonradan eklenen; bincode enum sırası: SONA) ---
    /// ⏱️ QC kapanış toleransı (ms); `ChainParams` dışında ayrı sentinelde durur.
    QcGraceMs,
}

impl ParamKey {
    pub fn channel(&self) -> GovChannel {
        use ParamKey::*;
        match self {
            MaxValidators | MaxBlockBytes | BlockIntervalMs | TBaseMs | EpochSeconds
            | ProbationEpochs | UptimeThresholdBps | MaxLivenessStrikes | IdleBlockIntervalS
            | MaxClockSkewMs | EvidenceMaxAgeEpochs | BondLockSeconds | MaxPerProvider
            | MaxPerRegion | MaxPerOperator | TimelockEpochs | GovVotingEpochs | QcGraceMs => {
                GovChannel::Consensus
            }
            _ => GovChannel::Economic,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParamUpdate {
    pub key: ParamKey,
    /// Hedef değer (tüm alanlar u128'e sığar; dar alanlara checked-cast).
    pub value: u128,
}

/// Yamayı uygular (boş/yinelenen anahtar ve taşma reddi + `validate()`). Saf.
/// `QcGraceMs` burada reddedilir; yürütme `apply_param_updates_with_grace` kullanır.
pub fn apply_param_updates(base: &ChainParams, updates: &[ParamUpdate]) -> Result<ChainParams> {
    if updates.iter().any(|u| u.key == ParamKey::QcGraceMs) {
        return Err(ZagrosError::ConfigError(
            "QcGraceMs icin apply_param_updates_with_grace kullanilmali".into(),
        ));
    }
    apply_param_updates_inner(base, updates)
}

/// `apply_param_updates` + `qc_grace_ms`. INV: sonuçta `grace ≤ t_base/4`
/// (grace değişse de, t_base değişse de), aksi halde yama bütünüyle reddedilir.
pub fn apply_param_updates_with_grace(
    base: &ChainParams,
    base_grace_ms: u64,
    updates: &[ParamUpdate],
) -> Result<(ChainParams, u64)> {
    let mut grace = base_grace_ms;
    let mut seen_grace = false;
    let mut rest: Vec<ParamUpdate> = Vec::new();
    for u in updates {
        if u.key == ParamKey::QcGraceMs {
            if seen_grace {
                return Err(ZagrosError::ConfigError(
                    "yinelenen anahtar: QcGraceMs".into(),
                ));
            }
            seen_grace = true;
            grace = u64::try_from(u.value).map_err(|_| {
                ZagrosError::ConfigError(format!("QcGraceMs icin deger tasar: {}", u.value))
            })?;
        } else {
            rest.push(*u);
        }
    }
    let p = if rest.is_empty() {
        if !seen_grace {
            return Err(ZagrosError::ConfigError("bos parametre yamasi".into()));
        }
        base.clone()
    } else {
        apply_param_updates_inner(base, &rest)?
    };
    validate_qc_grace(p.t_base_ms, grace)?;
    Ok((p, grace))
}

fn apply_param_updates_inner(base: &ChainParams, updates: &[ParamUpdate]) -> Result<ChainParams> {
    if updates.is_empty() {
        return Err(ZagrosError::ConfigError("bos parametre yamasi".into()));
    }
    let mut seen = std::collections::HashSet::new();
    let mut p = base.clone();
    for u in updates {
        if !seen.insert(u.key) {
            return Err(ZagrosError::ConfigError(format!(
                "yinelenen anahtar: {:?}",
                u.key
            )));
        }
        macro_rules! cast {
            ($t:ty) => {
                <$t>::try_from(u.value).map_err(|_| {
                    ZagrosError::ConfigError(format!("{:?} icin deger tasar: {}", u.key, u.value))
                })?
            };
        }
        use ParamKey::*;
        match u.key {
            MaxValidators => p.max_validators = cast!(u16),
            MaxBlockBytes => p.max_block_bytes = cast!(u64),
            BlockIntervalMs => p.block_interval_ms = cast!(u64),
            TBaseMs => p.t_base_ms = cast!(u64),
            EpochSeconds => p.epoch_seconds = cast!(u64),
            ProbationEpochs => p.probation_epochs = cast!(u32),
            UptimeThresholdBps => p.uptime_threshold_bps = cast!(u16),
            MaxLivenessStrikes => p.max_liveness_strikes = cast!(u32),
            IdleBlockIntervalS => p.idle_block_interval_s = cast!(u64),
            MaxClockSkewMs => p.max_clock_skew_ms = cast!(u64),
            EvidenceMaxAgeEpochs => p.evidence_max_age_epochs = cast!(u32),
            BondLockSeconds => p.bond_lock_seconds = cast!(u64),
            MaxPerProvider => p.max_per_provider = cast!(u16),
            MaxPerRegion => p.max_per_region = cast!(u16),
            MaxPerOperator => p.max_per_operator = cast!(u16),
            TimelockEpochs => p.timelock_epochs = cast!(u32),
            GovVotingEpochs => p.gov_voting_epochs = cast!(u32),
            MinValidatorStakeZerenya => p.min_validator_stake_zerenya = u.value,
            StakeHysteresisBps => p.stake_hysteresis_bps = cast!(u16),
            ApplicationFeeZerenya => p.application_fee_zerenya = u.value,
            ReserveFloorZerenyaPerDay => p.reserve_floor_zerenya_per_day = u.value,
            ReserveEndEpoch => p.reserve_end_epoch = cast!(u64),
            ReporterRewardCapBps => p.reporter_reward_cap_bps = cast!(u16),
            FalseDeclarationSlashBps => p.false_declaration_slash_bps = cast!(u16),
            VoteCapBps => p.vote_cap_bps = cast!(u16),
            StakerQuorumBps => p.staker_quorum_bps = cast!(u16),
            QcGraceMs => unreachable!("QcGraceMs ust katmanda ayristirilir"),
        }
    }
    p.validate()?;
    Ok(p)
}

#[cfg(test)]
mod qc_grace_tests {
    use super::*;

    #[test]
    fn grace_cap_is_quarter_of_t_base_and_updates_are_validated_both_ways() {
        let base = ChainParams::genesis_defaults(); // t_base 1500 → cap 375
        assert_eq!(qc_grace_cap_ms(base.t_base_ms), base.t_base_ms / 4);
        assert!(
            validate_qc_grace(base.t_base_ms, DEFAULT_QC_GRACE_MS).is_ok(),
            "varsayilan 200 sigmali"
        );
        // grace'i yükselt: sınır içinde OK, dışında RED
        let (p, g) = apply_param_updates_with_grace(
            &base,
            200,
            &[ParamUpdate {
                key: ParamKey::QcGraceMs,
                value: 375,
            }],
        )
        .unwrap();
        assert_eq!((p.t_base_ms, g), (base.t_base_ms, 375));
        assert!(apply_param_updates_with_grace(
            &base,
            200,
            &[ParamUpdate {
                key: ParamKey::QcGraceMs,
                value: 376
            }]
        )
        .is_err());
        // t_base'i KÜÇÜLT: mevcut grace artık sığmıyorsa yama reddedilir (ileride
        // timeout değişse de bugün güvenli olan grace sessizce tehlikeli olamaz)
        assert!(apply_param_updates_with_grace(
            &base,
            200,
            &[ParamUpdate {
                key: ParamKey::TBaseMs,
                value: 700
            }]
        )
        .is_err());
        assert!(apply_param_updates_with_grace(
            &base,
            100,
            &[ParamUpdate {
                key: ParamKey::TBaseMs,
                value: 700
            }]
        )
        .is_ok());
        // eski API QcGraceMs'i kabul etmez
        assert!(apply_param_updates(
            &base,
            &[ParamUpdate {
                key: ParamKey::QcGraceMs,
                value: 100
            }]
        )
        .is_err());
        // kodlama gidiş-dönüş
        assert_eq!(decode_qc_grace(&encode_qc_grace(200)).unwrap(), 200);
        assert!(decode_qc_grace(&[1, 2, 3]).is_err());
        assert_eq!(ParamKey::QcGraceMs.channel(), GovChannel::Consensus);
    }
}

/// Tipli öneri gövdesi (G12). `Text` = legacy serbest metin (davranış birebir
/// eski governance). Tipli türler SubmitProposal payload'ında `ZGOV1\0` magic
/// önekiyle taşınır, öneksiz her payload Text sayılır (geriye uyum).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ProposalAction {
    #[default]
    Text,
    ParamChange(Vec<ParamUpdate>),
    ScheduleUpgrade {
        target_ruleset: u32,
        binary_sha256: [u8; 32],
        activation_epoch: u64,
    },
    /// Kurucu admin yetkisinin bitişini ERKENE çeker; yalnız kısaltır, uzatma
    /// reddedilir. 🚨 Varyant SONA eklendi (bincode enum indeksi sıraya bağlı).
    ShortenAdminAuthority {
        end_timestamp: u64,
    },
    /// 🗳️ Faz B: adayı kümeye alır (validator oyuyla). Yürütme AYNI
    /// `apply_admin_approve` kapısından geçer, yalnız karar veren değişir.
    /// 🚨 Varyantlar SONA eklendi (bincode enum indeksi sıraya bağlı).
    ApproveValidator {
        target: String,
    },
    /// 🗳️ Faz B: bir validator'ü kümeden ÇIKARIR (staker oyuyla).
    /// Teminat `bond_lock_seconds` boyunca kilitli kalır (slash edilebilir).
    RemoveValidator {
        target: String,
    },
}

pub const GOV_PAYLOAD_MAGIC: &[u8; 6] = b"ZGOV1\0";

impl ProposalAction {
    /// Tipli önerinin kanalı; Text için None. ParamChange karışık-kanal ise Err.
    pub fn channel(&self) -> Result<Option<GovChannel>> {
        match self {
            ProposalAction::Text => Ok(None),
            ProposalAction::ScheduleUpgrade { .. } => Ok(Some(GovChannel::Consensus)),
            // Kurucu yetkisinin süresi konsensüs-seviyesi bir karardır.
            ProposalAction::ShortenAdminAuthority { .. } => Ok(Some(GovChannel::Consensus)),
            // 🗳️ Faz B: küme üyeliğine AKTİF validatörler ≥2/3 ile oy verir;
            // oybirliği aranmaz, tek "hayır" yeni üye alımını kilitleyemez.
            ProposalAction::ApproveValidator { .. } | ProposalAction::RemoveValidator { .. } => {
                Ok(Some(GovChannel::Consensus))
            }
            ProposalAction::ParamChange(updates) => {
                let mut ch: Option<GovChannel> = None;
                for u in updates {
                    let c = u.key.channel();
                    match ch {
                        None => ch = Some(c),
                        Some(existing) if existing != c => {
                            return Err(ZagrosError::ConfigError(
                                "tek oneride iki kanal karisamaz (consensus+economic)".into(),
                            ))
                        }
                        _ => {}
                    }
                }
                Ok(ch)
            }
        }
    }

    pub fn encode_payload(&self) -> Result<Vec<u8>> {
        let mut out = GOV_PAYLOAD_MAGIC.to_vec();
        let body = bincode::serialize(self)
            .map_err(|e| ZagrosError::ConfigError(format!("ProposalAction serialize: {e}")))?;
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Magic yoksa `Ok(None)` (legacy Text yolu); magic var ama gövde bozuksa Err
    /// (fail-closed: bozuk tipli öneri sessizce Text'e DÜŞMEZ).
    pub fn decode_payload(payload: &[u8]) -> Result<Option<ProposalAction>> {
        if payload.len() < GOV_PAYLOAD_MAGIC.len()
            || &payload[..GOV_PAYLOAD_MAGIC.len()] != GOV_PAYLOAD_MAGIC
        {
            return Ok(None);
        }
        bincode::deserialize(&payload[GOV_PAYLOAD_MAGIC.len()..])
            .map(Some)
            .map_err(|e| ZagrosError::ConfigError(format!("bozuk tipli oneri: {e}")))
    }
}
