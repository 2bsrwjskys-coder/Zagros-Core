// Zagros Network, Secure Bridge Multi-Signature System
// Cross-chain bridge with cryptographic signature verification

use ed25519_dalek::{Signature as Ed25519Signature, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use zagros_state::State;
use zagros_types::*;

/// `BridgeManager`'ın diske yazılan sayaçları, yetkili listesi (her zaman
/// config'den gelir) veya `proposals` (ayrı ayrı `Bridge_<id>` anahtarlarında
/// tutulur) burada YER ALMAZ, sadece mutasyona uğrayan küçük sayaçlar.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BridgeManagerMeta {
    daily_minted: u128,
    last_reset: u64,
    nonce_counter: u64,
}

/// Zincir seviyesi günlük mint sayacı. 🛡️ Gerçek kayan 86400 sn pencere
/// (`(timestamp, amount)` girdileri); takvim günü kovası gece yarısında tavanın 2 katına izin verirdi.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DailyMintTracker {
    entries: Vec<(u64, u128)>,
}

/// `BridgeManager::daily_mint_status`'ın salt-okunur sonucu, bkz. o
/// fonksiyonun doc yorumu. Alanlar ham (18 ondalık) birimde.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DailyMintStatus {
    /// O anki yapılandırılmış GLOBAL günlük tavan.
    pub daily_limit: u128,
    /// Kayan 24 saatlik pencerede şu ana kadar basılmış toplam (tüm
    /// kullanıcılar dahil, tek bir paylaşılan sayaç).
    pub minted_in_window: u128,
    /// `daily_limit - minted_in_window` (tavan zaten dolmuşsa 0).
    pub remaining: u128,
    /// Tavan doluysa, en eski girdi pencereden çıkıp EN AZ bir miktar
    /// kapasite serbest kalana kadar geçmesi gereken saniye. Tavan dolu
    /// değilse 0.
    pub retry_after_secs: u64,
}

/// Göç için: `DailyMintTracker`'ın eski takvim günü kovası şekli; yalnız eski
/// disk kayıtlarını okumak için, yeni kod kullanmamalı (bincode kendini tanımlamaz).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DailyMintTrackerV0 {
    day: u64,
    minted: u128,
}

// 🚨 DOĞRUDAN YENİ ALAN EKLEMEYİN: bincode eski kaydı okuyamaz, düğüm açılamaz.
// Gerçek koruma `deserialize_with_migration` V0 fallback; yeni alan `BridgeProposalV{N}` + göç + test.

/// Bridge transaction proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeProposal {
    pub proposal_id: Hash,
    pub tx_type: BridgeTxType,
    pub amount: u128,
    pub recipient: Address,
    pub source_chain: String,
    pub source_tx_hash: String,
    pub timestamp: u64,
    pub signatures: Vec<BridgeSignature>,
    pub executed: bool,
    pub nonce: u64, // ✅ Replay attack koruması
    /// true ise basılan ZERENYA anında ZAGROS'a çevrilir (`BridgeMintAndSwap`),
    /// false ise düz `BridgeMint`. Eski kayıtlar V0 fallback ile false okunur.
    #[serde(default)]
    pub auto_swap: bool,
    /// 🛡️ Kullanıcının `lockTokens`'ta belirttiği minimum ZAGROS çıktısı
    /// (`auto_swap=true` iken `swap_amount_out_min` ile uygulanır). Eski
    /// öneriler için V0 fallback 0 verir (korumasız, eski davranış).
    #[serde(default)]
    pub amount_out_min: u128,
    /// 🎟️ Burn yönü EIP-712 claim fişleri: haberciler yazar, dApp okur, kullanıcı
    /// `claimTokens`ta sunar. Gizli değildir, tek başına eşiği sağlamaz.
    #[serde(default)]
    pub claim_vouchers: Vec<ClaimVoucher>,
}

/// `auto_swap`/`amount_out_min`/`claim_vouchers` eklenmeden ÖNCEKİ `BridgeProposal`
/// şekli. YALNIZCA `BridgeProposal::deserialize_with_migration`'ın eski disk
/// kayıtlarını okuyabilmesi için var, yeni kod bunu doğrudan KULLANMAMALI.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BridgeProposalV0 {
    proposal_id: Hash,
    tx_type: BridgeTxType,
    amount: u128,
    recipient: Address,
    source_chain: String,
    source_tx_hash: String,
    timestamp: u64,
    signatures: Vec<BridgeSignature>,
    executed: bool,
    nonce: u64,
}

impl From<BridgeProposalV0> for BridgeProposal {
    fn from(old: BridgeProposalV0) -> Self {
        BridgeProposal {
            proposal_id: old.proposal_id,
            tx_type: old.tx_type,
            amount: old.amount,
            recipient: old.recipient,
            source_chain: old.source_chain,
            source_tx_hash: old.source_tx_hash,
            timestamp: old.timestamp,
            signatures: old.signatures,
            executed: old.executed,
            nonce: old.nonce,
            auto_swap: false,
            amount_out_min: 0,
            claim_vouchers: Vec::new(),
        }
    }
}

impl BridgeProposal {
    /// Diskten `BridgeProposal` okur (`AccountState` ile aynı desen): önce güncel
    /// şekil, olmazsa `BridgeProposalV0`; o da başarısızsa gerçek bozulma, hata
    /// fırlatılır (fail-closed, varsayılan öneri UYDURULMAZ).
    fn deserialize_with_migration(bytes: &[u8]) -> std::result::Result<Self, String> {
        if let Ok(proposal) = bincode::deserialize::<BridgeProposal>(bytes) {
            return Ok(proposal);
        }
        bincode::deserialize::<BridgeProposalV0>(bytes)
            .map(BridgeProposal::from)
            .map_err(|e| {
                format!(
                    "BridgeProposal deserialize edilemedi (güncel VE V0 şekli denendi): {}",
                    e
                )
            })
    }
}

/// Tek bir habercinin ürettiği EIP-712 claim imzası.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClaimVoucher {
    /// İmzalayan habercinin Ethereum adresi (0x önekli, küçük harf).
    pub signer: String,
    /// 65 baytlık `r || s || v`, 0x önekli hex.
    pub signature: String,
}

/// Bridge transaction types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BridgeTxType {
    /// Mint ZERENYA (deposit from external chain)
    /// CRITICAL: Only ZERENYA can be minted, NEVER ZAGROS token
    Mint,
    /// Burn ZERENYA (withdraw to external chain)
    Burn,
}

/// Bridge authority signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeSignature {
    pub authority: Address,
    pub signature: Signature,
    pub public_key: Vec<u8>, // ✅ Public key eklendi
    pub timestamp: u64,
}

/// Bridge authority with public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeAuthority {
    pub address: Address,
    pub public_key: [u8; PUBLIC_KEY_LENGTH],
    pub is_active: bool,
}

/// 🛡️ Köprü yetkili kümesinin ZİNCİR ÜSTÜ kaydı (`BRIDGE_AUTHORITY_SET_KEY`).
/// Genesis'te bir kez yazılır; `validate_bridge_mint_proposal` her basımda
/// imzaları buna karşı doğrular, node'un `config.toml`'u sonucu ETKİLEMEZ.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnChainBridgeAuthoritySet {
    pub authorities: Vec<BridgeAuthority>,
    /// M-of-N eşiği (M). N = `authorities` içindeki AKTİF yetkili sayısı.
    pub required_signatures: u16,
}

impl OnChainBridgeAuthoritySet {
    /// Yazmadan ÖNCE doğrular, geçersiz bir küme zincire giremez.
    pub fn validate(&self) -> Result<()> {
        if self.authorities.is_empty() {
            return Err(ZagrosError::ConfigError(
                "kopru yetkili kumesi bos olamaz".into(),
            ));
        }
        if self.required_signatures == 0 {
            return Err(ZagrosError::ConfigError(
                "kopru required_signatures 0 olamaz (imzasiz basim demek olurdu)".into(),
            ));
        }
        let active = self.authorities.iter().filter(|a| a.is_active).count();
        if (self.required_signatures as usize) > active {
            return Err(ZagrosError::ConfigError(format!(
                "kopru esigi ({}) aktif yetkili sayisindan ({}) buyuk olamaz - hicbir oneri asla yurutulemezdi",
                self.required_signatures, active
            )));
        }
        // Yinelenen adres/anahtar, eşiği fiilen düşürür (aynı yetkili iki kez
        // sayılabilirdi), reddet.
        let mut seen_addr = std::collections::HashSet::new();
        let mut seen_key = std::collections::HashSet::new();
        for a in &self.authorities {
            if !seen_addr.insert(a.address.to_ascii_lowercase()) {
                return Err(ZagrosError::ConfigError(format!(
                    "kopru yetkili adresi yinelenmis: {}",
                    a.address
                )));
            }
            if !seen_key.insert(a.public_key) {
                return Err(ZagrosError::ConfigError(
                    "iki kopru yetkilisi AYNI acik anahtari kullaniyor - esik fiilen duser".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Zincir-üstü köprü yetkili kümesini okur. FAIL-CLOSED: kayıt yoksa/bozuksa
/// `Err`, sessizce "doğrulama yapma" moduna DÜŞÜLMEZ.
pub fn load_bridge_authority_set(state: &dyn State) -> Result<OnChainBridgeAuthoritySet> {
    let acc = state
        .get_account(&zagros_types::consensus::BRIDGE_AUTHORITY_SET_KEY.to_string())
        .map_err(BridgeManager::state_err)?;
    let Some(acc) = acc.filter(|a| !a.contract_code.is_empty()) else {
        return Err(ZagrosError::ConfigError(
            "kopru yetkili kumesi state'te YOK (genesis yazilmamis?) - basim dogrulanamaz,              fail-closed reddediliyor"
                .into(),
        ));
    };
    let set: OnChainBridgeAuthoritySet = bincode::deserialize(&acc.contract_code)
        .map_err(|e| ZagrosError::ConfigError(format!("kopru yetkili kumesi bozuk: {e}")))?;
    set.validate()?;
    Ok(set)
}

/// Zincir-üstü köprü yetkili kümesini yazar (genesis). Doğrulamadan geçmeyen
/// küme yazılmaz.
pub fn store_bridge_authority_set(
    state: &dyn State,
    set: &OnChainBridgeAuthoritySet,
) -> Result<()> {
    set.validate()?;
    let bytes = bincode::serialize(set)
        .map_err(|e| ZagrosError::Other(format!("kopru yetkili kumesi serialize hatasi: {e}")))?;
    let mut acc = AccountState::default();
    acc.contract_code = bytes;
    state
        .set_account(
            &zagros_types::consensus::BRIDGE_AUTHORITY_SET_KEY.to_string(),
            acc,
        )
        .map_err(BridgeManager::state_err)
}

/// 🛡️ Önerinin imzalarını zincir üstü kümeye karşı Ed25519 `verify_strict`
/// ile doğrular, kaç FARKLI geçerli yetkilinin imzaladığını döner. Canlı
/// `BridgeManager` gerektirmez, bu yüzden konsensüs yolunda kullanılabilir.
pub fn count_valid_signatures_onchain(
    set: &OnChainBridgeAuthoritySet,
    proposal: &BridgeProposal,
    chain_id: u64,
) -> usize {
    let base_message = BridgeManager::create_signing_message(proposal, chain_id);
    let mut seen: HashSet<String> = HashSet::new();
    for sig in &proposal.signatures {
        let canonical = sig.authority.to_ascii_lowercase();
        if seen.contains(&canonical) {
            continue;
        }
        let Some(auth) = set
            .authorities
            .iter()
            .find(|a| a.address.to_ascii_lowercase() == canonical)
        else {
            continue;
        };
        if !auth.is_active {
            continue;
        }
        if sig.public_key.len() != PUBLIC_KEY_LENGTH {
            continue;
        }
        if sig.public_key.as_slice() != auth.public_key.as_slice() {
            continue;
        }
        let bound = BridgeManager::bind_timestamp_to_message(&base_message, sig.timestamp);
        if BridgeManager::verify_ed25519(&bound, &sig.signature, &auth.public_key) {
            seen.insert(canonical);
        }
    }
    seen.len()
}

/// Bridge multi-sig manager with enhanced security
pub struct BridgeManager {
    /// List of authorized bridge authorities with public keys
    authorities: HashMap<Address, BridgeAuthority>,

    /// Required signatures (e.g., 3 out of 5)
    required_signatures: usize,

    /// Pending proposals
    proposals: HashMap<Hash, BridgeProposal>,

    // 🛡️ İşlenmiş kaynaklar ayrı `BridgeProcessedSource_<chain>|<hash>` anahtarında
    // (O(1), restart'ı atlatır); yalnız bellek haritası restart sonrası körleşir, mükerrer mint olurdu.
    /// Daily mint limit (anti-exploit)
    daily_mint_limit: u128,

    /// Daily minted amount
    daily_minted: u128,

    /// Last reset timestamp (using system time)
    last_reset: u64,

    /// Time-lock period (24 hours)
    timelock_period: u64,

    /// Chain ID (replay attack koruması)
    chain_id: u64,

    /// Proposal nonce counter (replay attack koruması)
    nonce_counter: u64,

    /// 🎟️ Claim fişi doğrulama bağlamı (Ethereum tarafı). `None` ise fiş kabulü
    /// KAPALIDIR (fail-closed), yapılandırma eksikken doğrulanmamış fiş
    /// saklamaktansa hiç saklamamak yeğdir.
    claim_context: Option<ClaimContext>,
}

/// Claim fişlerinin doğrulanabilmesi için gereken Ethereum tarafı bilgileri.
/// `ZagrosBridgeGateway`'in EIP-712 domain'i ve `isRelayer` kümesiyle eşleşmeli.
#[derive(Debug, Clone)]
pub struct ClaimContext {
    /// Ethereum zincir kimliği (mainnet = 1).
    pub chain_id: u64,
    /// Deploy edilmiş gateway adresi (EIP-712 verifyingContract).
    pub gateway: [u8; 20],
    /// Kasadan çekilecek ERC20 (PAXG, Pax Gold).
    pub token: [u8; 20],
    /// Hedef ERC20'nin ondalık sayısı (PAXG = 18). 🚨 Dijeste giren tutar bu
    /// ondalığa ölçeklenir; relayer ile aynı değer kullanılmazsa tüm fişler reddedilir.
    pub token_decimals: u32,
    /// Habercilerin Ethereum adresleri, kontrattaki `isRelayer` kümesi.
    pub relayers: Vec<[u8; 20]>,
}

impl BridgeManager {
    /// Create new bridge manager with multi-sig and public keys
    pub fn new(
        authorities: Vec<BridgeAuthority>,
        required_signatures: usize,
        chain_id: u64,
    ) -> Self {
        assert!(
            required_signatures <= authorities.len(),
            "Required signatures cannot exceed authorities"
        );
        assert!(required_signatures >= 2, "At least 2 signatures required");

        let mut auth_map = HashMap::new();
        for auth in authorities {
            auth_map.insert(auth.address.clone(), auth);
        }

        Self {
            authorities: auth_map,
            required_signatures,
            proposals: HashMap::new(),
            daily_mint_limit: 10_000_000 * TOKEN_DECIMAL, // 10M ZERENYA per day
            daily_minted: 0,
            last_reset: 0,
            timelock_period: 24 * 60 * 60, // 24 hours in seconds
            chain_id,
            nonce_counter: 0,
            // Fiş kabulü varsayılan olarak KAPALI; CLI `with_claim_context` ile açar.
            claim_context: None,
        }
    }

    /// Default bridge authority set for multi-sig validation
    pub fn default_authorities() -> Vec<BridgeAuthority> {
        let mut authorities = Vec::new();
        for i in 1..=3 {
            let mut seed = [0u8; 32];
            seed[0] = i as u8;
            let signing_key = SigningKey::from_bytes(&seed);
            let public_key = signing_key.verifying_key().to_bytes();
            let address = Self::derive_address_from_public_key(&public_key);

            authorities.push(BridgeAuthority {
                address,
                public_key,
                is_active: true,
            });
        }
        authorities
    }

    /// Default bridge manager using a secure 2-of-3 threshold
    pub fn default_bridge_manager(chain_id: u64) -> Self {
        Self::new(Self::default_authorities(), 2, chain_id)
    }

    pub fn derive_address_from_public_key(public_key: &[u8; PUBLIC_KEY_LENGTH]) -> Address {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(public_key);
        let result = hasher.finalize();
        let eth_hex = hex::encode(&result[12..]);
        format!("0x{}", eth_hex)
    }

    /// Create bridge proposal (mint or burn)
    #[allow(clippy::too_many_arguments)]
    pub fn create_proposal(
        &mut self,
        tx_type: BridgeTxType,
        amount: u128,
        recipient: Address,
        source_chain: String,
        source_tx_hash: String,
        timestamp: u64,
        auto_swap: bool,
        amount_out_min: u128,
        current_time: u128,
        state: &dyn State,
    ) -> Result<Hash> {
        // ✅ SECURITY: Validate timestamp
        let current_time_secs = (current_time / 1000) as u64;

        // Timestamp cannot be too old (max 1 hour ago)
        if timestamp < current_time_secs.saturating_sub(3600) {
            return Err(ZagrosError::Other(
                "Timestamp too old (max 1 hour)".to_string(),
            ));
        }

        // Timestamp cannot be in future (max 5 minutes ahead for clock skew)
        if timestamp > current_time_secs + 300 {
            return Err(ZagrosError::Other(
                "Timestamp too far in future (max 5 min)".to_string(),
            ));
        }

        // 🛡️ DEDUP: aynı (source_chain, source_tx_hash) için ikinci öneri
        // oluşturulmaz, mevcut id döner (idempotent); ikinci relayer onu
        // keşfedip eş imzalar, çift mint olmaz.
        if let Some(existing) = self
            .proposals
            .values()
            .find(|p| p.source_chain == source_chain && p.source_tx_hash == source_tx_hash)
        {
            return Ok(existing.proposal_id);
        }

        // 🛡️ Yukarıdaki kontrol yalnız bellekteki önerilere bakar; restart sonrası
        // yürütülmüş öneriler orada yoktur. Kalıcı küme de kontrol edilir ve
        // karşılığı verilmiş işlem için yeni öneri açıkça reddedilir.
        if self.is_source_processed(&source_chain, &source_tx_hash, state)? {
            return Err(ZagrosError::BridgeError(format!(
                "Bu kaynak islem zaten yurutuldu, ikinci kez islenemez: {}|{}",
                source_chain, source_tx_hash
            )));
        }

        // ✅ SECURITY: Generate unique proposal ID with nonce
        self.nonce_counter += 1;
        let proposal_id = self.generate_proposal_id(
            &source_chain,
            &source_tx_hash,
            &recipient,
            amount,
            self.nonce_counter,
        );

        // Check if proposal already exists (nonce-collision safety net)
        if self.proposals.contains_key(&proposal_id) {
            return Err(ZagrosError::Other("Proposal already exists".to_string()));
        }

        // Sıfır tutarlı öneri meşru olamaz; nonce ve bekleyen indeks tüketmesin.
        if amount == 0 {
            return Err(ZagrosError::BridgeError(
                "Bridge proposal amount must be non-zero".to_string(),
            ));
        }

        // Mint için günlük limit. 🚨 Yalnız erken ret KOLAYLIĞI: `daily_minted`
        // bellek sayacı üretimde artmaz; gerçek, atlatılamaz kontrol
        // `check_and_record_daily_mint`'te (Executor, zincir durumu üzerinden).
        if tx_type == BridgeTxType::Mint {
            // 🛡️ Per-tx tavan öneri OLUŞTURMA anında da uygulanır: aksi halde
            // yürütme hep reddedilir, dedup da aynı yürütülemez id'yi döndürür ve
            // depozito kalıcı olarak takılı kalırdı; fail-closed baştan reddedilir.
            if amount > MAX_SINGLE_BRIDGE_MINT {
                return Err(ZagrosError::BridgeError(
                    "BridgeMint exceeds per-tx cap".to_string(),
                ));
            }

            self.reset_daily_limit_if_needed(current_time);

            if self.daily_minted + amount > self.daily_mint_limit {
                return Err(ZagrosError::Other(format!(
                    "Daily mint limit exceeded: {} + {} > {}",
                    self.daily_minted, amount, self.daily_mint_limit
                )));
            }
        }

        let proposal = BridgeProposal {
            proposal_id,
            tx_type,
            amount,
            recipient,
            source_chain,
            source_tx_hash,
            timestamp,
            signatures: Vec::new(),
            executed: false,
            nonce: self.nonce_counter,
            auto_swap,
            amount_out_min,
            claim_vouchers: Vec::new(),
        };

        self.proposals.insert(proposal_id, proposal);

        Ok(proposal_id)
    }

    /// Sign a bridge proposal with cryptographic verification
    pub fn sign_proposal(
        &mut self,
        proposal_id: &Hash,
        authority: Address,
        signature: Signature,
        public_key: Vec<u8>,
        timestamp: u64,
        current_time: u128,
    ) -> Result<()> {
        // ✅ SECURITY: Verify authority exists and is active
        let auth = self.authorities.get(&authority).ok_or(ZagrosError::Other(
            "Unauthorized bridge authority".to_string(),
        ))?;

        if !auth.is_active {
            return Err(ZagrosError::Other("Authority is not active".to_string()));
        }

        // ✅ SECURITY: Verify public key matches authority
        if public_key.len() != PUBLIC_KEY_LENGTH {
            return Err(ZagrosError::Other("Invalid public key length".to_string()));
        }

        let mut pk_array = [0u8; PUBLIC_KEY_LENGTH];
        pk_array.copy_from_slice(&public_key);

        if pk_array != auth.public_key {
            return Err(ZagrosError::Other(
                "Public key does not match authority".to_string(),
            ));
        }

        // Get proposal
        // Get proposal for validation (immutable borrow)
        let proposal = self
            .proposals
            .get(proposal_id)
            .ok_or(ZagrosError::Other("Proposal not found".to_string()))?;

        // Check if already executed
        if proposal.executed {
            return Err(ZagrosError::Other("Proposal already executed".to_string()));
        }

        // Check if authority already signed
        if proposal.signatures.iter().any(|s| s.authority == authority) {
            return Err(ZagrosError::Other("Authority already signed".to_string()));
        }

        // ✅ SECURITY: Validate signature timestamp ÖNCE, imza artık bu
        // timestamp'e bağlı (bind_timestamp_to_message) olduğundan, doğrulama
        // yapılmadan mesajı türetemeyiz; sıra bilerek verify'den öne alındı.
        let current_time_secs = (current_time / 1000) as u64;
        if timestamp < current_time_secs.saturating_sub(3600) {
            return Err(ZagrosError::Other(
                "Signature timestamp too old".to_string(),
            ));
        }
        if timestamp > current_time_secs + 300 {
            return Err(ZagrosError::Other(
                "Signature timestamp too far in future".to_string(),
            ));
        }

        // ✅ SECURITY: Verify signature cryptographically. İmza, öneri alanlarına
        // (tx_type dahil) VE bu imzanın kendi timestamp'ine bağlı mesaj üzerinde
        // doğrulanır (🛡️ FAZ4 signature context binding).
        let base_message = Self::create_signing_message(proposal, self.chain_id);
        let bound_message = Self::bind_timestamp_to_message(&base_message, timestamp);
        if !self.verify_signature(&bound_message, &signature, &pk_array) {
            return Err(ZagrosError::Other(
                "Invalid signature - cryptographic verification failed".to_string(),
            ));
        }

        // Now get mutable borrow to add signature
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or(ZagrosError::Other("Proposal not found".to_string()))?;

        // Add signature
        proposal.signatures.push(BridgeSignature {
            authority,
            signature,
            public_key,
            timestamp,
        });

        Ok(())
    }

    /// Önerinin onay imzası için kanonik mesaj. `&self` almaz: yalnız `chain_id`
    /// gerekir, böylece uzak istemci (zagros-relayer) aynı mesajı bağımsız üretip imzalar.
    pub fn create_signing_message(proposal: &BridgeProposal, chain_id: u64) -> Vec<u8> {
        use sha3::{Digest, Keccak256};

        let mut hasher = Keccak256::new();
        hasher.update(proposal.proposal_id);
        // 🛡️ tx_type imzaya dahil: "mint" imzaları aynı alanlı "burn"e oynatılamaz.
        hasher.update(format!("{:?}", proposal.tx_type).as_bytes());
        hasher.update(proposal.amount.to_le_bytes());
        hasher.update(proposal.recipient.as_bytes());
        hasher.update(proposal.source_chain.as_bytes());
        hasher.update(proposal.source_tx_hash.as_bytes());
        hasher.update(proposal.timestamp.to_le_bytes());
        hasher.update(proposal.nonce.to_le_bytes());
        // 🛡️ Slippage talebi imzaya dahil; yoksa bir yetkili sessizce düşürebilirdi.
        hasher.update(proposal.amount_out_min.to_le_bytes());
        // 🛡️ `auto_swap` imzaya dahil: kötü üretici bayrağı çevirip istenmeyen swap
        // ya da sıfır kayma korumasıyla swap zorlayabilirdi.
        hasher.update([proposal.auto_swap as u8]);
        hasher.update(chain_id.to_le_bytes());

        hasher.finalize().to_vec()
    }

    /// 🛡️ Yetkilinin kendi `signature.timestamp`'ini kanonik mesaja bağlar;
    /// imza kapsamı dışında kalsaydı tazelik kontrolü imza bozulmadan atlatılabilirdi.
    pub fn bind_timestamp_to_message(base_message: &[u8], sig_timestamp: u64) -> Vec<u8> {
        use sha3::{Digest, Keccak256};

        let mut hasher = Keccak256::new();
        hasher.update(base_message);
        hasher.update(b"SIG_TS:");
        hasher.update(sig_timestamp.to_le_bytes());
        hasher.finalize().to_vec()
    }

    /// `zagros_proposeBridgeAction` kanonik mesajı (öneri henüz yok, ham alanlar
    /// hash'lenir, `tx_type` dahil). `&self` almaz: uzak istemci üretebilsin.
    #[allow(clippy::too_many_arguments)]
    pub fn propose_request_message(
        tx_type: &BridgeTxType,
        recipient: &Address,
        amount: u128,
        source_chain: &str,
        source_tx_hash: &str,
        timestamp: u64,
        auto_swap: bool,
        amount_out_min: u128,
        chain_id: u64,
    ) -> Vec<u8> {
        use sha3::{Digest, Keccak256};

        let mut hasher = Keccak256::new();
        hasher.update(b"BRIDGE_PROPOSE:");
        hasher.update(format!("{:?}", tx_type).as_bytes());
        hasher.update(recipient.as_bytes());
        hasher.update(amount.to_le_bytes());
        hasher.update(source_chain.as_bytes());
        hasher.update(source_tx_hash.as_bytes());
        hasher.update(timestamp.to_le_bytes());
        hasher.update([auto_swap as u8]);
        hasher.update(amount_out_min.to_le_bytes());
        hasher.update(chain_id.to_le_bytes());

        hasher.finalize().to_vec()
    }

    /// Bu yöneticinin köprü isteklerini doğrularken kullandığı chain_id.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Var olan öneri gerektirmeden bir isteğin aktif köprü yetkilisinden
    /// geldiğini doğrular: yetkili aktif, `public_key` kayıtlıyla eşleşiyor ve
    /// `signature` o anahtarla `message` üzerinde geçerli Ed25519 imzası.
    pub fn authenticate_authority_request(
        &self,
        authority: &Address,
        public_key: &[u8; PUBLIC_KEY_LENGTH],
        message: &[u8],
        signature: &Signature,
    ) -> bool {
        let Some(auth) = self.authorities.get(authority) else {
            return false;
        };
        if !auth.is_active {
            return false;
        }
        if &auth.public_key != public_key {
            return false;
        }
        self.verify_signature(message, signature, public_key)
    }

    /// İmzaları kendi kümesine karşı bağımsız doğrular (RPC beyanına güvenmez);
    /// tx_type ve tazelik uygulamaz (burn önerileri 24 saat bekler), eşik çağıranda.
    pub fn count_valid_authority_signatures(&self, proposal: &BridgeProposal) -> usize {
        let base_message = Self::create_signing_message(proposal, self.chain_id);
        let mut seen = HashSet::new();
        for sig in &proposal.signatures {
            if seen.contains(&sig.authority) {
                continue;
            }
            if sig.public_key.len() != PUBLIC_KEY_LENGTH {
                continue;
            }
            let mut pk = [0u8; PUBLIC_KEY_LENGTH];
            pk.copy_from_slice(&sig.public_key);
            // 🛡️ FAZ4: her imza kendi timestamp'ine bağlı mesaj üzerinde doğrulanır.
            let bound_message = Self::bind_timestamp_to_message(&base_message, sig.timestamp);
            if self.authenticate_authority_request(
                &sig.authority,
                &pk,
                &bound_message,
                &sig.signature,
            ) {
                seen.insert(sig.authority.clone());
            }
        }
        seen.len()
    }

    /// Configured M-of-N threshold (kaç geçerli imza gerekir).
    pub fn required_signatures(&self) -> usize {
        self.required_signatures
    }

    /// Yapılandırılmış toplam yetkili (relayer) sayısı (N, M-of-N'deki N).
    pub fn authorities_count(&self) -> usize {
        self.authorities.len()
    }

    /// Zaman kilidi süresi (saniye), bir önerinin yürütülebilmesi için
    /// `proposal.timestamp` üzerinden bu kadar zaman geçmiş olmalı.
    pub fn timelock_period(&self) -> u64 {
        self.timelock_period
    }

    /// Verify Ed25519 signature
    fn verify_signature(
        &self,
        message: &[u8],
        signature: &Signature,
        public_key: &[u8; PUBLIC_KEY_LENGTH],
    ) -> bool {
        Self::verify_ed25519(message, signature, public_key)
    }

    /// Ed25519 doğrulamanın tek kaynağı; `&self` almaz ki konsensüs yolu canlı
    /// instance olmadan aynı kuralı uygulasın.
    pub fn verify_ed25519(
        message: &[u8],
        signature: &Signature,
        public_key: &[u8; PUBLIC_KEY_LENGTH],
    ) -> bool {
        // Signature must be exactly 64 bytes
        if signature.len() != 64 {
            return false;
        }

        // Parse signature
        let sig = match Ed25519Signature::from_slice(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        // Parse public key
        let key = match VerifyingKey::from_bytes(public_key) {
            Ok(k) => k,
            Err(_) => return false,
        };

        // 🛡️ `verify_strict`: legacy `verify` non-kanonik S ve küçük mertebe
        // anahtarları kabul edip malleability'ye kapı aralıyordu.
        key.verify_strict(message, &sig).is_ok()
    }

    /// Check if proposal can be executed
    pub fn can_execute(&self, proposal_id: &Hash, current_time: u128) -> Result<bool> {
        let proposal = self
            .proposals
            .get(proposal_id)
            .ok_or(ZagrosError::Other("Proposal not found".to_string()))?;
        Ok(Self::proposal_is_executable(
            proposal,
            self.required_signatures,
            self.timelock_period,
            current_time,
        ))
    }

    /// 🛡️ Tek yürütülebilirlik kuralı (saf). 🚨 İmza doğrulamaz, sayar: listeye
    /// yalnız `sign_proposal()` ekler ve veri kontrollü yollardan yazılır.
    pub fn proposal_is_executable(
        proposal: &BridgeProposal,
        required_signatures: usize,
        timelock_secs: u64,
        current_time: u128,
    ) -> bool {
        if proposal.executed {
            return false;
        }
        if proposal.signatures.len() < required_signatures {
            return false;
        }
        let current_time_secs = (current_time / 1000) as u64;
        if current_time_secs < proposal.timestamp + timelock_secs {
            return false;
        }
        true
    }

    /// Execute bridge proposal (after multi-sig validation)
    pub fn execute_proposal(
        &mut self,
        proposal_id: &Hash,
        current_time: u128,
        state: &dyn State,
    ) -> Result<BridgeProposal> {
        // Validate can execute
        if !self.can_execute(proposal_id, current_time)? {
            return Err(ZagrosError::Other(
                "Proposal cannot be executed yet".to_string(),
            ));
        }

        // 🛡️ TOCTOU: günlük limit yürütme anında yeniden doğrulanır; yalnız
        // oluşturma anında kontrol edilseydi 0 sayaçla açılan N öneri limiti katlardı.
        // `&mut self` + Mutex ile serileştiğinden kontrol atomik.
        let (tx_type, amount) = {
            let p = self
                .proposals
                .get(proposal_id)
                .ok_or(ZagrosError::Other("Proposal not found".to_string()))?;
            (p.tx_type.clone(), p.amount)
        };
        if tx_type == BridgeTxType::Mint {
            self.reset_daily_limit_if_needed(current_time);
            if self.daily_minted + amount > self.daily_mint_limit {
                return Err(ZagrosError::Other(format!(
                    "Daily mint limit exceeded at execution: {} + {} > {}",
                    self.daily_minted, amount, self.daily_mint_limit
                )));
            }
        }

        // 🛡️ SON KAPI: para burada yaratılır. `create_proposal` mükerrer önerinin
        // OLUŞMASINI, bu ise başka yoldan gelmiş mükerrerin YÜRÜTÜLMESİNİ engeller.
        let (src_chain, src_hash) = {
            let p = self
                .proposals
                .get(proposal_id)
                .ok_or(ZagrosError::Other("Proposal not found".to_string()))?;
            (p.source_chain.clone(), p.source_tx_hash.clone())
        };
        if self.is_source_processed(&src_chain, &src_hash, state)? {
            return Err(ZagrosError::BridgeError(format!(
                "Mukerrer yurutme reddedildi - bu kaynak islem zaten islendi: {}|{}",
                src_chain, src_hash
            )));
        }

        // Get and mark as executed
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or(ZagrosError::Other("Proposal not found".to_string()))?;

        proposal.executed = true;

        // Update daily mint counter
        if proposal.tx_type == BridgeTxType::Mint {
            self.daily_minted += proposal.amount;
        }

        let executed = proposal.clone();
        self.mark_source_processed(&src_chain, &src_hash, state)?;

        Ok(executed)
    }

    /// Get proposal status
    pub fn get_proposal(&self, proposal_id: &Hash) -> Option<&BridgeProposal> {
        self.proposals.get(proposal_id)
    }

    /// ⏳ Zaman kilidi (saniye). Varsayılan 24 saat ÜRETİMDE ÖYLE KALMALI: sahte
    /// çekim fark edilip `pause()` ile durdurulabilsin. 🚨 Düğüm ve relayer aynı
    /// değeri kullanmalı; relayer `executable_at`'i kendi kilidiyle hesaplar.
    pub fn with_timelock_secs(mut self, timelock_secs: u64) -> Self {
        self.timelock_period = timelock_secs;
        self
    }

    /// Claim fişi doğrulama bağlamını bağlar (CLI, config.toml'dan çağırır).
    /// Verilmezse fiş kabulü kapalı kalır.
    pub fn with_claim_context(mut self, context: ClaimContext) -> Self {
        self.claim_context = Some(context);
        self
    }

    /// 🎟️ Burn önerisine EIP-712 fişi ekler, ÖNCE DOĞRULAR (dijest + haberci
    /// kümesi); çöp fiş depolamayı şişirir, geçersiz fiş kullanıcı gas'ını yakardı. Aynı haberci: günceller.
    pub fn add_claim_voucher(&mut self, proposal_id: &Hash, signature_hex: &str) -> Result<String> {
        let context = self.claim_context.clone().ok_or_else(|| {
            ZagrosError::BridgeError(
                "Claim voucher acceptance is disabled: [bridge.ethereum] is not configured"
                    .to_string(),
            )
        })?;

        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or_else(|| ZagrosError::BridgeError("Proposal not found".to_string()))?;

        if proposal.tx_type != BridgeTxType::Burn {
            return Err(ZagrosError::BridgeError(
                "Claim vouchers only apply to burn (withdraw) proposals".to_string(),
            ));
        }

        // Fiş, kontratın `claimTokens` çağrısına birebir bu alanlarla gider.
        let recipient = eip712::parse_eth_address(&proposal.recipient).ok_or_else(|| {
            ZagrosError::BridgeError("Proposal recipient is not a valid Ethereum address".into())
        })?;
        let zagros_tx_hash = eip712::parse_h256(&proposal.source_tx_hash).ok_or_else(|| {
            ZagrosError::BridgeError("Proposal source_tx_hash is not a valid 32-byte hash".into())
        })?;

        // 🔢 ZERENYA (18 ondalık) → hedef ERC20 ondalığı. Kontrata giden tutar budur,
        // dolayısıyla dijeste de bu girmelidir. Paylaşılan `bridge_amount` modülü
        // relayer tarafında da aynı ölçeklemeyi yapar.
        let scaled = bridge_amount::scale_zerenya_to_token(proposal.amount, context.token_decimals)
            .ok_or_else(|| {
                ZagrosError::BridgeError(format!(
                    "Burn amount {} does not scale to a non-zero {}-decimal token amount",
                    proposal.amount, context.token_decimals
                ))
            })?;

        let digest = eip712::claim_digest(
            context.chain_id,
            &context.gateway,
            &context.token,
            &recipient,
            &eip712::amount_to_be_bytes(scaled.token_amount),
            &zagros_tx_hash,
        );

        let raw = hex::decode(signature_hex.strip_prefix("0x").unwrap_or(signature_hex))
            .map_err(|_| ZagrosError::BridgeError("Signature is not valid hex".to_string()))?;
        if raw.len() != 65 {
            return Err(ZagrosError::BridgeError(format!(
                "Signature must be 65 bytes (r||s||v), got {}",
                raw.len()
            )));
        }
        let mut signature = [0u8; 65];
        signature.copy_from_slice(&raw);

        let signer = eip712::recover_claim_signer(&digest, &signature).ok_or_else(|| {
            ZagrosError::BridgeError("Signature does not recover to any signer".to_string())
        })?;

        if !context.relayers.iter().any(|known| known == &signer) {
            return Err(ZagrosError::BridgeError(
                "Signature is not from a configured bridge relayer".to_string(),
            ));
        }

        let signer_hex = format!("0x{}", hex::encode(signer));
        let signature_hex = format!("0x{}", hex::encode(signature));

        if let Some(existing) = proposal
            .claim_vouchers
            .iter_mut()
            .find(|voucher| voucher.signer == signer_hex)
        {
            existing.signature = signature_hex;
        } else {
            proposal.claim_vouchers.push(ClaimVoucher {
                signer: signer_hex.clone(),
                signature: signature_hex,
            });
        }

        Ok(signer_hex)
    }

    /// Yürütülmemiş tüm önerileri döner; öneriyi oluşturmamış yetkili imzalaması
    /// gerekenleri keşfeder (`proposal_id` sunucu içi `nonce_counter`'a bağlı).
    pub fn get_pending_proposals(&self) -> Vec<&BridgeProposal> {
        self.proposals.values().filter(|p| !p.executed).collect()
    }

    /// En yeni `limit` öneriyi (yürütülmüş dahil, zamana göre azalan) döner;
    /// paneller geçmiş imza aktivitesini görsün (`get_pending_proposals`
    /// yürütülür yürütülmez düşürür, sakin dönemde panel boş görünürdü).
    pub fn get_recent_proposals(&self, limit: usize) -> Vec<&BridgeProposal> {
        let mut proposals: Vec<&BridgeProposal> = self.proposals.values().collect();
        proposals.sort_by_key(|b| std::cmp::Reverse(b.timestamp));
        proposals.truncate(limit);
        proposals
    }

    /// Reset daily limit if 24 hours passed (using system time)
    fn reset_daily_limit_if_needed(&mut self, current_time: u128) {
        let current_time_secs = (current_time / 1000) as u64;

        // ✅ SECURITY: Prevent time going backwards
        if current_time_secs < self.last_reset {
            // Time went backwards, don't reset limit!
            return;
        }

        if current_time_secs >= self.last_reset + 24 * 60 * 60 {
            self.daily_minted = 0;
            self.last_reset = current_time_secs;
        }
    }

    /// Generate deterministic proposal ID with replay attack protection
    fn generate_proposal_id(
        &self,
        source_chain: &str,
        source_tx_hash: &str,
        recipient: &str,
        amount: u128,
        nonce: u64,
    ) -> Hash {
        use sha3::{Digest, Keccak256};

        let mut hasher = Keccak256::new();
        hasher.update(source_chain.as_bytes());
        hasher.update(source_tx_hash.as_bytes());
        hasher.update(recipient.as_bytes());
        hasher.update(amount.to_le_bytes());
        hasher.update(nonce.to_le_bytes());
        hasher.update(self.chain_id.to_le_bytes());

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    // 💾 KALICILIK (RocksDB), restart'ta sayaçlar/öneriler kaybolmasın

    /// Bir harici kaynak işlemin kimliği. Küçük harfe indiriyoruz: aynı hash'in
    /// farklı harf düzeniyle gelmesi ikinci bir kayıt gibi görünmemeli.
    fn source_key(source_chain: &str, source_tx_hash: &str) -> String {
        format!(
            "{}|{}",
            source_chain.to_lowercase(),
            source_tx_hash.to_lowercase()
        )
    }

    /// 🛠️ Operatör kurtarma aracı: kaynak işlemi "işlendi" işaretler (koruma
    /// öncesi mükerrer öneriler için). 🚨 Yanlış işaretleme meşru yatırmayı kalıcı kilitler.
    pub fn mark_source_processed(
        &self,
        source_chain: &str,
        source_tx_hash: &str,
        state: &dyn State,
    ) -> Result<()> {
        Self::mark_source_processed_in_state(source_chain, source_tx_hash, state)
    }

    /// `mark_source_processed`'ın `&self`'siz (statik) hali, executor'ın mint
    /// yürütme yolu canlı bir `BridgeManager` instance'ı olmadan da AYNI
    /// "işlendi" kaydını yazabilsin diye (çift-basım kilidinin yazma tarafı).
    pub fn mark_source_processed_in_state(
        source_chain: &str,
        source_tx_hash: &str,
        state: &dyn State,
    ) -> Result<()> {
        state
            .set_account(
                &Self::processed_source_key(source_chain, source_tx_hash),
                AccountState::default(),
            )
            .map_err(Self::state_err)
    }

    /// Bu harici kaynak işlem daha önce YÜRÜTÜLDÜ mü (yani karşılığı zaten
    /// verildi mi)? Yeniden başlatmadan etkilenmez, artık doğrudan `state`'e
    /// bakıyor (O(1) nokta okuması), bellek-içi bir kopya YOK.
    pub fn is_source_processed(
        &self,
        source_chain: &str,
        source_tx_hash: &str,
        state: &dyn State,
    ) -> Result<bool> {
        Self::is_source_processed_in_state(source_chain, source_tx_hash, state)
    }

    /// `is_source_processed`'ın `&self`'siz (statik) hali, bkz.
    /// `mark_source_processed_in_state`.
    pub fn is_source_processed_in_state(
        source_chain: &str,
        source_tx_hash: &str,
        state: &dyn State,
    ) -> Result<bool> {
        Ok(state
            .get_account(&Self::processed_source_key(source_chain, source_tx_hash))
            .map_err(Self::state_err)?
            .is_some())
    }

    /// Tek bir harici kaynak işlemin O(1) varlık kontrolü/işaretleme anahtarı
    /// (tüm kümeyi tek blob'da tutmak her yazımda BAŞTAN SONA serileştirme olurdu).
    fn processed_source_key(source_chain: &str, source_tx_hash: &str) -> Address {
        format!(
            "BridgeProcessedSource_{}",
            Self::source_key(source_chain, source_tx_hash)
        )
    }

    /// Eski (item-4-öncesi) tüm-küme blob'unun anahtarı, artık yalnızca
    /// tek-seferlik göç taramasında (bkz. `load_from_state`) okunuyor.
    fn legacy_processed_sources_key() -> Address {
        "BridgeProcessedSources".to_string()
    }

    /// item-4 göçünün tamamlandığını işaretleyen sentinel anahtar (R8, bkz.
    /// `MigrationRecord`). Varlığı, `legacy_processed_sources_key()` blob'unun
    /// bir daha OKUNMAYACAĞININ garantisidir, sonraki her açılışta no-op.
    fn processed_sources_migration_key() -> Address {
        "__MIGRATION_BridgeProcessedSourcesFanOut__".to_string()
    }

    fn meta_key() -> Address {
        "__BRIDGE_MANAGER_META__".to_string()
    }

    fn pending_index_key() -> Address {
        "__BRIDGE_PENDING_PROPOSALS__".to_string()
    }

    /// 🛡️ `pub`: P2P katmanının (bkz. `zagros-network`'ün `collect_bridge_proposals`/
    /// `ingest_bridge_proposals`'ı) blokla birlikte taşınan köprü önerilerini
    /// alıcı tarafta AYNI aktif anahtara yazabilmesi için dışa açıldı.
    pub fn proposal_state_key(proposal_id: &Hash) -> Address {
        format!("Bridge_{}", hex::encode(proposal_id))
    }

    /// Yürütülmüş önerinin kalıcı denetim anahtarı; aktif anahtar yalnız bekleyenleri tutar.
    fn proposal_archive_key(proposal_id: &Hash) -> Address {
        format!("BridgeArchive_{}", hex::encode(proposal_id))
    }

    /// Arşivlenmiş (yürütülmüş) bir öneriyi doğrudan diskten okur,
    /// `load_proposal_from_state`'in arşiv eşleniği. `zagros_getBridgeProposal`
    /// RPC'sinin fallback zincirinin son halkası.
    pub fn load_archived_proposal_from_state(
        state: &dyn State,
        proposal_id: &Hash,
    ) -> Result<Option<BridgeProposal>> {
        match state
            .get_account(&Self::proposal_archive_key(proposal_id))
            .map_err(Self::state_err)?
        {
            Some(account) if !account.contract_code.is_empty() => {
                let proposal = BridgeProposal::deserialize_with_migration(&account.contract_code)
                    .map_err(|e| {
                    ZagrosError::Other(format!("Corrupt archived bridge proposal: {}", e))
                })?;
                Ok(Some(proposal))
            }
            _ => Ok(None),
        }
    }

    /// 🛡️ P2P follower senkronu: mint yürütmesi RPC ile oluşturulmuş öneriye bağlı;
    /// blokla taşınmazsa follower state_root'ta ayrışır. Her mint'in önerisini toplar.
    pub fn collect_proposals_for_relay(
        state: &dyn State,
        transactions: &[Transaction],
    ) -> Vec<BridgeProposal> {
        transactions
            .iter()
            .filter(|tx| matches!(tx.tx_type, TxType::BridgeMint | TxType::BridgeMintAndSwap))
            .filter_map(|tx| {
                Self::load_proposal_from_state(state, &tx.tx_id)
                    .ok()
                    .flatten()
                    .or_else(|| {
                        Self::load_archived_proposal_from_state(state, &tx.tx_id)
                            .ok()
                            .flatten()
                    })
            })
            .collect()
    }

    /// 🛡️ Blok üretirken ön koşul: eşiği dolduran öneriyi bu düğümün state'inden
    /// sağlayamayan üretici o `BridgeMint`i bloğa koymamalı; işlem mempool'da
    /// bekler, öneriyi taşıyan üretici sıraya gelince bloklanır. Köprü dışı işlemde `true`.
    pub fn can_supply_proposal_for(state: &dyn State, tx: &Transaction) -> bool {
        if !matches!(tx.tx_type, TxType::BridgeMint | TxType::BridgeMintAndSwap) {
            return true;
        }
        let Ok(set) = load_bridge_authority_set(state) else {
            return false;
        };
        let proposal = Self::load_proposal_from_state(state, &tx.tx_id)
            .ok()
            .flatten()
            .or_else(|| {
                Self::load_archived_proposal_from_state(state, &tx.tx_id)
                    .ok()
                    .flatten()
            });
        let Some(proposal) = proposal else {
            return false;
        };
        count_valid_signatures_onchain(&set, &proposal, zagros_types::CHAIN_ID)
            >= set.required_signatures as usize
    }

    /// Alıcı taraf: blokla gelen önerileri AKTİF anahtara yazar, `executed` kasıtlı
    /// `false` (bloktaki tx normal akışla işler). İşlemlerden ÖNCE çağrılmalı.
    pub fn ingest_relayed_proposals(state: &dyn State, proposals: &[BridgeProposal]) -> Result<()> {
        // Zincir-ustu yetkili kumesi: hem "yazilabilir mi" kararinin hem de
        // esigin TEK kaynagi. Her dugumde AYNI oldugu icin karar da her
        // dugumde ayni cikar. Okunamiyorsa hicbir sey yazilmaz (fail-closed).
        let Ok(set) = load_bridge_authority_set(state) else {
            return Ok(());
        };
        for proposal in proposals {
            // 🛡️ Tek kural: zincir üstü kümeye karşı eşiği dolduran GEÇERLİ imzalar
            // varsa yazılır (yerel kopyayı ezer), yoksa yazılmaz. Karar yalnız blok +
            // state'e baktığından her düğümde aynı; asıl savunma `validate_bridge_mint_proposal`.
            let gecerli = count_valid_signatures_onchain(&set, proposal, zagros_types::CHAIN_ID);
            if gecerli < set.required_signatures as usize {
                continue;
            }
            let key = Self::proposal_state_key(&proposal.proposal_id);
            let mut proposal = proposal.clone();
            proposal.executed = false;
            let bytes = bincode::serialize(&proposal).map_err(|e| {
                ZagrosError::Other(format!(
                    "Bridge proposal (P2P relay) serialize hatası: {}",
                    e
                ))
            })?;
            let mut account = AccountState::default();
            account.contract_code = bytes;
            state.set_account(&key, account).map_err(Self::state_err)?;
        }
        Ok(())
    }

    /// Mutabakat: bellek içi haritadan state'in bekleyen listesinde olmayanları
    /// budar; yoksa yürütülmüş öneri RPC'de süresiz görünürdü.
    pub fn prune_ids_not_in(&mut self, still_pending: &[Hash]) {
        self.proposals.retain(|id, _| still_pending.contains(id));
    }

    pub(crate) fn state_err(err: impl std::fmt::Display) -> ZagrosError {
        ZagrosError::Other(format!("Bridge state I/O error: {}", err))
    }

    /// Sayaçları diske yazar; her `create_proposal`/`execute_proposal` sonrası
    /// çağrılmalı, yoksa restart sayaçları sessizce sıfırlar.
    pub fn persist_meta(&self, state: &dyn State) -> Result<()> {
        let meta = BridgeManagerMeta {
            daily_minted: self.daily_minted,
            last_reset: self.last_reset,
            nonce_counter: self.nonce_counter,
        };
        let bytes = bincode::serialize(&meta)
            .map_err(|e| ZagrosError::Other(format!("Failed to serialize bridge meta: {}", e)))?;
        let mut account = AccountState::default();
        account.contract_code = bytes;
        state
            .set_account(&Self::meta_key(), account)
            .map_err(Self::state_err)?;

        // İşlenmiş kaynak işaretleri burada yazılmaz (her çağrı kendi O(1)
        // anahtarını yazar); `persist_meta` yine flush eder, sözleşme bozulmasın.
        state.flush().map_err(Self::state_err)
    }

    /// Öneriyi diske yazar ve indeksi günceller. 🚨 SONUNDA `flush()`: öneriler
    /// RPC yolundan bloksuz yazılır, flush olmasa sessiz zincirde restart'ta yok olurdu (canlıda yaşandı).
    pub fn persist_proposal(&self, state: &dyn State, proposal_id: &Hash) -> Result<()> {
        let proposal = self
            .proposals
            .get(proposal_id)
            .ok_or_else(|| ZagrosError::Other("Proposal not found".to_string()))?;
        let bytes = bincode::serialize(proposal).map_err(|e| {
            ZagrosError::Other(format!("Failed to serialize bridge proposal: {}", e))
        })?;
        let mut account = AccountState::default();
        account.contract_code = bytes;
        state
            .set_account(&Self::proposal_state_key(proposal_id), account)
            .map_err(Self::state_err)?;

        self.persist_pending_index(state)?;
        state.flush().map_err(Self::state_err)
    }

    /// Yürütülmeyi bekleyen (executed=false) öneri kimliklerinin listesini
    /// diske yazar, Faz C'nin arka plan yürütücüsü diskte tam taramaya
    /// gerek kalmadan bekleyenleri bulabilsin diye.
    fn persist_pending_index(&self, state: &dyn State) -> Result<()> {
        let pending: Vec<Hash> = self
            .proposals
            .values()
            .filter(|p| !p.executed)
            .map(|p| p.proposal_id)
            .collect();
        let bytes = bincode::serialize(&pending)
            .map_err(|e| ZagrosError::Other(format!("Failed to serialize pending index: {}", e)))?;
        let mut account = AccountState::default();
        account.contract_code = bytes;
        state
            .set_account(&Self::pending_index_key(), account)
            .map_err(Self::state_err)
    }

    /// Diskten `BridgeManager` inşa eder. Yetkili listesi/eşik/zincir ID HER
    /// ZAMAN config'den (eski diskteki yetkililer dirilmesin); sayaçlar ve
    /// bekleyen öneriler diskten.
    pub fn load_from_state(
        state: &dyn State,
        authorities: Vec<BridgeAuthority>,
        required_signatures: usize,
        chain_id: u64,
    ) -> Result<Self> {
        let mut manager = Self::new(authorities, required_signatures, chain_id);

        if let Some(account) = state
            .get_account(&Self::meta_key())
            .map_err(Self::state_err)?
        {
            if !account.contract_code.is_empty() {
                let meta: BridgeManagerMeta = bincode::deserialize(&account.contract_code)
                    .map_err(|e| ZagrosError::Other(format!("Corrupt bridge meta: {}", e)))?;
                manager.daily_minted = meta.daily_minted;
                manager.last_reset = meta.last_reset;
                manager.nonce_counter = meta.nonce_counter;
            }
        }

        // 🛡️ Tek seferlik göç: eski tek blob küme O(1) anahtarlara dağıtılır
        // (replay korumasında boşluk olmasın); sentinel ile sonra no-op.
        if state
            .get_account(&Self::processed_sources_migration_key())
            .map_err(Self::state_err)?
            .is_none()
        {
            let mut migrated_count = 0usize;
            if let Some(account) = state
                .get_account(&Self::legacy_processed_sources_key())
                .map_err(Self::state_err)?
            {
                if !account.contract_code.is_empty() {
                    let legacy: Vec<String> = bincode::deserialize(&account.contract_code)
                        .map_err(|e| {
                            ZagrosError::Other(format!("Corrupt bridge processed sources: {}", e))
                        })?;
                    for combined_key in legacy {
                        // `combined_key` zaten `source_key`'in çıktı formatında
                        // (`"{chain}|{hash}"`, küçük harfe indirilmiş).
                        let key = format!("BridgeProcessedSource_{}", combined_key);
                        state
                            .set_account(&key, AccountState::default())
                            .map_err(Self::state_err)?;
                        migrated_count += 1;
                    }
                }
            }
            let now_secs = std::time::UNIX_EPOCH
                .elapsed()
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let migration_record = zagros_types::MigrationRecord {
                version: 1,
                completed_at_unix_secs: now_secs,
            };
            let migration_bytes = bincode::serialize(&migration_record).map_err(|e| {
                ZagrosError::Other(format!("Failed to serialize migration record: {}", e))
            })?;
            let mut migration_account = AccountState::default();
            migration_account.contract_code = migration_bytes;
            state
                .set_account(&Self::processed_sources_migration_key(), migration_account)
                .map_err(Self::state_err)?;
            state.flush().map_err(Self::state_err)?;
            if migrated_count > 0 {
                tracing::info!(
                    "🛠️ Migration: BridgeProcessedSourcesFanOut v1 tamamlandı ({} kaynak işlem \
                     yeni O(1) anahtar şemasına taşındı).",
                    migrated_count
                );
            }
        }

        if let Some(account) = state
            .get_account(&Self::pending_index_key())
            .map_err(Self::state_err)?
        {
            if !account.contract_code.is_empty() {
                let pending_ids: Vec<Hash> =
                    bincode::deserialize(&account.contract_code).map_err(|e| {
                        ZagrosError::Other(format!("Corrupt bridge pending index: {}", e))
                    })?;
                for proposal_id in pending_ids {
                    if let Some(proposal) = Self::load_proposal_from_state(state, &proposal_id)? {
                        manager.proposals.insert(proposal_id, proposal);
                    }
                }
            }
        }

        Ok(manager)
    }

    /// Tek bir öneriyi doğrudan diskten okur, yürütülmüş olsa (ve bu yüzden
    /// bellekteki bekleyen listede olmasa) bile, durum sorguları için.
    pub fn load_proposal_from_state(
        state: &dyn State,
        proposal_id: &Hash,
    ) -> Result<Option<BridgeProposal>> {
        match state
            .get_account(&Self::proposal_state_key(proposal_id))
            .map_err(Self::state_err)?
        {
            Some(account) if !account.contract_code.is_empty() => {
                let proposal = BridgeProposal::deserialize_with_migration(&account.contract_code)
                    .map_err(|e| {
                    ZagrosError::Other(format!("Corrupt bridge proposal: {}", e))
                })?;
                Ok(Some(proposal))
            }
            _ => Ok(None),
        }
    }

    /// 🛡️ Mint payload'ı önerinin kendisidir (imzalarıyla): her düğüm aynı
    /// baytlardan doğrular, tahrif imzaları bozar; `amount_out_min` imza kapsamında.
    pub fn encode_proposal_payload(proposal: &BridgeProposal) -> Result<Vec<u8>> {
        bincode::serialize(proposal).map_err(|e| {
            ZagrosError::Other(format!("Kopru onerisi payload serialize hatasi: {}", e))
        })
    }

    /// `encode_proposal_payload`'in tersi. Bos payload fail-closed reddedilir,
    /// "payload yoksa state'e bak" gibi bir geri dusus BILEREK YOKTUR, cunku
    /// tam olarak o geri dusus dugumler arasi ayrismayi dogururdu.
    pub fn decode_proposal_payload(payload: &[u8]) -> Result<BridgeProposal> {
        if payload.is_empty() {
            return Err(ZagrosError::BridgeError(
                "Kopru mint islemi oneriyi payload'inda tasimiyor".to_string(),
            ));
        }
        BridgeProposal::deserialize_with_migration(payload).map_err(|e| {
            ZagrosError::BridgeError(format!("Kopru onerisi payload'i cozulemedi: {}", e))
        })
    }

    /// Yürütülen öneriyi arşivler; `mark_executed_in_state`'ten farkı state'ten
    /// okumayıp doğrulanmış payload sürümünü yazması: her düğümde AYNI baytlar,
    /// aynı state_root. Yalnız `validate_bridge_mint_proposal` geçtikten sonra çağrılır.
    pub fn archive_executed_proposal(state: &dyn State, proposal: &BridgeProposal) -> Result<()> {
        let proposal_id = &proposal.proposal_id;
        let mut arsivlenecek = proposal.clone();
        arsivlenecek.executed = true;

        let archive_bytes = bincode::serialize(&arsivlenecek).map_err(|e| {
            ZagrosError::Other(format!("Failed to serialize bridge proposal: {}", e))
        })?;
        let mut archive_account = AccountState::default();
        archive_account.contract_code = archive_bytes;
        state
            .set_account(&Self::proposal_archive_key(proposal_id), archive_account)
            .map_err(Self::state_err)?;

        // Aktif anahtar VARSA bosaltilir (mantiksal silme). Yoksa, ki oneriyi
        // hic gormemis bir dugumde normaldir, yapacak bir sey yoktur.
        if let Some(account) = state
            .get_account(&Self::proposal_state_key(proposal_id))
            .map_err(Self::state_err)?
        {
            if !account.contract_code.is_empty() {
                let mut emptied_account = account;
                emptied_account.contract_code = Vec::new();
                state
                    .set_account(&Self::proposal_state_key(proposal_id), emptied_account)
                    .map_err(Self::state_err)?;
            }
        }

        // Bekleyen indeksten cikar (varsa), yurutucu her taramada tekrar
        // denemesin.
        if let Some(index_account) = state
            .get_account(&Self::pending_index_key())
            .map_err(Self::state_err)?
        {
            if !index_account.contract_code.is_empty() {
                let mut pending: Vec<Hash> = bincode::deserialize(&index_account.contract_code)
                    .map_err(|e| {
                        ZagrosError::Other(format!("Corrupt bridge pending index: {}", e))
                    })?;
                let before = pending.len();
                pending.retain(|id| id != proposal_id);
                if pending.len() != before {
                    let mut updated = index_account;
                    updated.contract_code = bincode::serialize(&pending).map_err(|e| {
                        ZagrosError::Other(format!("Failed to serialize pending index: {}", e))
                    })?;
                    state
                        .set_account(&Self::pending_index_key(), updated)
                        .map_err(Self::state_err)?;
                }
            }
        }
        Ok(())
    }

    /// 🛡️ Öneriyi basımla aynı checkpoint'te atomik `executed=true` işaretler;
    /// CLI kendi başına finalize etmez.
    pub fn mark_executed_in_state(state: &dyn State, proposal_id: &Hash) -> Result<()> {
        let key = Self::proposal_state_key(proposal_id);
        let account = state
            .get_account(&key)
            .map_err(Self::state_err)?
            .ok_or_else(|| ZagrosError::Other("Proposal not found".to_string()))?;
        let mut proposal = BridgeProposal::deserialize_with_migration(&account.contract_code)
            .map_err(|e| ZagrosError::Other(format!("Corrupt bridge proposal: {}", e)))?;
        proposal.executed = true;

        // 🛡️ Yürütülmüş öneri kalıcı `BridgeArchive_<hex>` anahtarına yazılır
        // (denetim kaydı, `zagros_getBridgeProposal` fallback'i), aktif
        // `Bridge_<hex>` boşaltılır (mantıksal silme). Aynı atomik checkpoint içinde.
        let archive_bytes = bincode::serialize(&proposal).map_err(|e| {
            ZagrosError::Other(format!("Failed to serialize bridge proposal: {}", e))
        })?;
        let mut archive_account = AccountState::default();
        archive_account.contract_code = archive_bytes;
        state
            .set_account(&Self::proposal_archive_key(proposal_id), archive_account)
            .map_err(Self::state_err)?;

        let mut emptied_account = account;
        emptied_account.contract_code = Vec::new();
        state
            .set_account(&key, emptied_account)
            .map_err(Self::state_err)?;

        // Bekleyen indeksten çıkar; yoksa yürütücü her taramada tekrar dener (gürültü).
        if let Some(index_account) = state
            .get_account(&Self::pending_index_key())
            .map_err(Self::state_err)?
        {
            if !index_account.contract_code.is_empty() {
                let mut pending: Vec<Hash> = bincode::deserialize(&index_account.contract_code)
                    .map_err(|e| {
                        ZagrosError::Other(format!("Corrupt bridge pending index: {}", e))
                    })?;
                let before = pending.len();
                pending.retain(|id| id != proposal_id);
                if pending.len() != before {
                    let mut updated = index_account;
                    updated.contract_code = bincode::serialize(&pending).map_err(|e| {
                        ZagrosError::Other(format!("Failed to serialize pending index: {}", e))
                    })?;
                    state
                        .set_account(&Self::pending_index_key(), updated)
                        .map_err(Self::state_err)?;
                }
            }
        }
        Ok(())
    }

    /// Günlük mint sayacının state anahtarı; `BridgeManagerMeta.daily_minted`
    /// yalnız canlı instance belleğini yansıtır, zincir seviyesindeki gerçek sayaç budur.
    fn daily_mint_tracker_key() -> Address {
        "BridgeDailyMintTracker".to_string()
    }

    /// 🛡️ Zincir seviyesi günlük mint limiti; basımla aynı checkpoint'te, basımdan
    /// ÖNCE. Başarısızsa basım yapılmaz (fail-closed); revert olursa sayaç da geri alınır.
    pub fn check_and_record_daily_mint(
        state: &dyn State,
        amount: u128,
        block_timestamp_secs: u64,
        daily_mint_limit: u128,
    ) -> Result<()> {
        let key = Self::daily_mint_tracker_key();
        let mut tracker: DailyMintTracker = match state
            .get_account(&key)
            .map_err(Self::state_err)?
        {
            Some(account) if !account.contract_code.is_empty() => {
                bincode::deserialize::<DailyMintTracker>(&account.contract_code)
                    .or_else(|_| {
                        // Eski takvim günü kovasından göç: kovadaki miktar
                        // ŞİMDİ basılmış tek girdi sayılır (fazla saymayı tercih eden güvenli varsayım).
                        bincode::deserialize::<DailyMintTrackerV0>(&account.contract_code).map(
                            |v0| DailyMintTracker {
                                entries: if v0.minted > 0 {
                                    vec![(block_timestamp_secs, v0.minted)]
                                } else {
                                    Vec::new()
                                },
                            },
                        )
                    })
                    .map_err(|e| ZagrosError::Other(format!("Corrupt daily mint tracker: {}", e)))?
            }
            _ => DailyMintTracker {
                entries: Vec::new(),
            },
        };

        // GERÇEK kayan pencere: 86400 saniyeden eski girdileri buda, KALANLARIN
        // toplamını al, takvim/kova sınırından TAMAMEN bağımsız.
        let window_start = block_timestamp_secs.saturating_sub(86_400);
        tracker.entries.retain(|(ts, _)| *ts > window_start);
        let minted_in_window: u128 = tracker.entries.iter().map(|(_, amt)| *amt).sum();

        let new_minted = minted_in_window
            .checked_add(amount)
            .ok_or_else(|| ZagrosError::BridgeError("Daily mint counter overflow".to_string()))?;
        if new_minted > daily_mint_limit {
            return Err(ZagrosError::BridgeError(format!(
                "Daily mint limit exceeded on-chain (kayan 24s pencere): {} + {} > {}",
                minted_in_window, amount, daily_mint_limit
            )));
        }
        tracker.entries.push((block_timestamp_secs, amount));

        let bytes = bincode::serialize(&tracker).map_err(|e| {
            ZagrosError::Other(format!("Failed to serialize daily mint tracker: {}", e))
        })?;
        let mut account = state
            .get_account(&key)
            .map_err(Self::state_err)?
            .unwrap_or_default();
        account.contract_code = bytes;
        state.set_account(&key, account).map_err(Self::state_err)?;
        Ok(())
    }

    /// Salt okunur günlük mint durumu (aynı kayan pencere mantığı); dApp kullanıcıyı
    /// PAXG kilitlemeye göndermeden önce kalan hakkı sorabilsin.
    pub fn daily_mint_status(
        state: &dyn State,
        block_timestamp_secs: u64,
        daily_mint_limit: u128,
    ) -> Result<DailyMintStatus> {
        let key = Self::daily_mint_tracker_key();
        let tracker: DailyMintTracker = match state.get_account(&key).map_err(Self::state_err)? {
            Some(account) if !account.contract_code.is_empty() => {
                bincode::deserialize::<DailyMintTracker>(&account.contract_code)
                    .or_else(|_| {
                        bincode::deserialize::<DailyMintTrackerV0>(&account.contract_code).map(
                            |v0| DailyMintTracker {
                                entries: if v0.minted > 0 {
                                    vec![(block_timestamp_secs, v0.minted)]
                                } else {
                                    Vec::new()
                                },
                            },
                        )
                    })
                    .map_err(|e| ZagrosError::Other(format!("Corrupt daily mint tracker: {}", e)))?
            }
            _ => DailyMintTracker {
                entries: Vec::new(),
            },
        };

        let window_start = block_timestamp_secs.saturating_sub(86_400);
        let active: Vec<&(u64, u128)> = tracker
            .entries
            .iter()
            .filter(|(ts, _)| *ts > window_start)
            .collect();
        let minted_in_window: u128 = active.iter().map(|(_, amt)| *amt).sum();
        let remaining = daily_mint_limit.saturating_sub(minted_in_window);
        // Tavan dolu değilse 0; doluysa en eski aktif girdi pencereden çıkınca
        // en az o kadar kapasite açılır ("bundan ÖNCE kesinlikle dolu", garanti değil).
        let retry_after_secs = if remaining > 0 {
            0
        } else {
            active
                .iter()
                .map(|(ts, _)| {
                    ts.saturating_add(86_400)
                        .saturating_sub(block_timestamp_secs)
                })
                .min()
                .unwrap_or(0)
        };

        Ok(DailyMintStatus {
            daily_limit: daily_mint_limit,
            minted_in_window,
            remaining,
            retry_after_secs,
        })
    }

    /// `swap::swap_amount_out_min`'in çözdüğü 68 bayt ABI benzeri payload'ın
    /// kodlayıcısı (`BridgeMintAndSwap` kurulurken). İlk 36 bayt okunmaz,
    /// yalnız bytes[36..68] minimum çıktıdır; sıfırla doldurmak yeterli.
    pub fn encode_amount_out_min_payload(min_out: u128) -> Vec<u8> {
        let mut payload = vec![0u8; 68];
        let be_bytes = alloy_primitives::U256::from(min_out).to_be_bytes::<32>();
        payload[36..68].copy_from_slice(&be_bytes);
        payload
    }

    /// Burn önerisinin gerçek zincir üstü yakmaya karşılık geldiğini doğrular
    /// (`create_proposal`dan önce); yoksa tek kötü yetkili uydurma burn'ü iki
    /// dürüst yetkiliye imzalatırdı. "Kayıt yok" ile "sahte" ayırt edilemez, ikisi de ret.
    pub fn verify_source_burn_matches(
        state: &dyn State,
        source_tx_hash: &str,
        expected_sender: &Address,
        expected_amount: u128,
    ) -> Result<()> {
        let mut tx_id = [0u8; 32];
        hex::decode_to_slice(source_tx_hash.trim_start_matches("0x"), &mut tx_id).map_err(
            |_| {
                ZagrosError::BridgeError(format!(
                    "Gecersiz source_tx_hash formati (32 bayt hex bekleniyor): {}",
                    source_tx_hash
                ))
            },
        )?;

        let record = crate::Executor::find_bridge_burn_record(state, &tx_id)
            .map_err(|e| ZagrosError::Other(format!("Burn kaydi aranirken hata: {}", e)))?
            .ok_or_else(|| {
                ZagrosError::BridgeError(format!(
                    "Belirtilen kaynak islem (burn) zincirin gorunurluk indeksinde bulunamadi \
                 (uydurma bir islem olabilir VEYA cok eski oldugu icin budanmis olabilir): {}",
                    source_tx_hash
                ))
            })?;

        if record.sender != *expected_sender {
            return Err(ZagrosError::BridgeError(format!(
                "Burn kaydinin gonderen adresi ({}) onerideki alici ({}) ile eslesmiyor",
                record.sender, expected_sender
            )));
        }
        if record.amount != expected_amount {
            return Err(ZagrosError::BridgeError(format!(
                "Burn kaydinin miktari ({}) onerideki miktarla ({}) eslesmiyor",
                record.amount, expected_amount
            )));
        }

        Ok(())
    }

    /// Diskteki bekleyen-öneri indeksinden tüm bekleyen önerileri okur (Faz
    /// C'nin arka plan yürütücüsünün tarama döngüsü için).
    pub fn load_pending_proposals_from_state(state: &dyn State) -> Result<Vec<BridgeProposal>> {
        let account = match state
            .get_account(&Self::pending_index_key())
            .map_err(Self::state_err)?
        {
            Some(account) if !account.contract_code.is_empty() => account,
            _ => return Ok(Vec::new()),
        };
        let pending_ids: Vec<Hash> = bincode::deserialize(&account.contract_code)
            .map_err(|e| ZagrosError::Other(format!("Corrupt bridge pending index: {}", e)))?;

        let mut proposals = Vec::with_capacity(pending_ids.len());
        for proposal_id in pending_ids {
            if let Some(proposal) = Self::load_proposal_from_state(state, &proposal_id)? {
                proposals.push(proposal);
            }
        }
        Ok(proposals)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::collections::HashMap as StdHashMap;
    use std::sync::{Arc, Mutex};
    use zagros_state::manager::StateDbManager;
    use zagros_storage::{Storage, StorageEngine};

    #[derive(Default)]
    struct MemoryStorage {
        values: Mutex<StdHashMap<Vec<u8>, Vec<u8>>>,
    }

    impl Storage for MemoryStorage {
        fn get(&self, key: &[u8]) -> zagros_primitives::Result<Option<Vec<u8>>> {
            Ok(self.values.lock().unwrap().get(key).cloned())
        }
        fn put(&self, key: &[u8], value: &[u8]) -> zagros_primitives::Result<()> {
            self.values
                .lock()
                .unwrap()
                .insert(key.to_vec(), value.to_vec());
            Ok(())
        }
        fn delete(&self, key: &[u8]) -> zagros_primitives::Result<()> {
            self.values.lock().unwrap().remove(key);
            Ok(())
        }
        fn contains(&self, key: &[u8]) -> zagros_primitives::Result<bool> {
            Ok(self.values.lock().unwrap().contains_key(key))
        }
        fn list_keys(&self) -> zagros_primitives::Result<Vec<Vec<u8>>> {
            Ok(self.values.lock().unwrap().keys().cloned().collect())
        }
    }

    impl StorageEngine for MemoryStorage {
        fn write_batch(&self, kvs: &[(Vec<u8>, Option<Vec<u8>>)]) -> zagros_primitives::Result<()> {
            let mut values = self.values.lock().unwrap();
            for (key, value) in kvs {
                match value {
                    Some(v) => {
                        values.insert(key.clone(), v.clone());
                    }
                    None => {
                        values.remove(key);
                    }
                }
            }
            Ok(())
        }
    }

    fn test_state() -> Arc<dyn State> {
        Arc::new(StateDbManager::new(Arc::new(MemoryStorage::default())))
    }

    fn create_test_authorities() -> Vec<BridgeAuthority> {
        let mut authorities = Vec::new();
        for i in 1..=5 {
            // Create deterministic test keys
            let mut seed = [0u8; 32];
            seed[0] = i as u8;
            let signing_key = SigningKey::from_bytes(&seed);
            let public_key = signing_key.verifying_key().to_bytes();

            authorities.push(BridgeAuthority {
                address: format!("zcxAUTH{}_00000000000000000000000000{}", i, i),
                public_key,
                is_active: true,
            });
        }
        authorities
    }

    fn current_time_ms() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    }

    #[test]
    fn test_bridge_multi_sig_with_verification() {
        let authorities = create_test_authorities();
        let mut bridge = BridgeManager::new(authorities.clone(), 3, CHAIN_ID);
        let now = current_time_ms();
        let state = test_state();

        // Create proposal
        let proposal_id = bridge
            .create_proposal(
                BridgeTxType::Mint,
                50 * TOKEN_DECIMAL,
                "zcxRECIPIENT_00000000000000000000001".to_string(),
                "Ethereum".to_string(),
                "0x123abc".to_string(),
                (now / 1000) as u64,
                false,
                0,
                now,
                state.as_ref(),
            )
            .unwrap();

        // Cannot execute without signatures
        assert!(!bridge.can_execute(&proposal_id, now).unwrap());
    }

    fn create_default_bridge_signers() -> Vec<SigningKey> {
        let mut keys = Vec::new();
        for i in 1..=3 {
            let mut seed = [0u8; 32];
            seed[0] = i as u8;
            keys.push(SigningKey::try_from(seed.as_slice()).expect("seed is 32 bytes"));
        }
        keys
    }

    /// 🛡️ `tx_type` imzada: mint imzaları burn önerisine oynatılamaz.
    #[test]
    fn signature_is_bound_to_tx_type() {
        use ed25519_dalek::Signer;
        let bridge = BridgeManager::default_bridge_manager(CHAIN_ID);
        let now = current_time_ms();
        let sig_ts = (now / 1000) as u64;

        let mut mint_proposal = BridgeProposal {
            proposal_id: [0x11; 32],
            tx_type: BridgeTxType::Mint,
            amount: 500 * TOKEN_DECIMAL,
            recipient: "0x0000000000000000000000000000000000000009".to_string(),
            source_chain: "Ethereum".to_string(),
            source_tx_hash: "0xbind".to_string(),
            timestamp: sig_ts,
            signatures: Vec::new(),
            executed: false,
            nonce: 1,
            auto_swap: false,
            amount_out_min: 0,
            claim_vouchers: Vec::new(),
        };
        let message = BridgeManager::create_signing_message(&mint_proposal, bridge.chain_id());
        let bound = BridgeManager::bind_timestamp_to_message(&message, sig_ts);
        for key in create_default_bridge_signers().iter().take(2) {
            mint_proposal.signatures.push(BridgeSignature {
                authority: BridgeManager::derive_address_from_public_key(
                    &key.verifying_key().to_bytes(),
                ),
                signature: key.sign(&bound).to_bytes().to_vec(),
                public_key: key.verifying_key().to_bytes().to_vec(),
                timestamp: sig_ts,
            });
        }
        // Mint olarak imzalar geçerli.
        assert_eq!(bridge.count_valid_authority_signatures(&mint_proposal), 2);

        // Aynı imzaları bir "burn" önerisine taşı → mesaj tx_type üzerinden değişir,
        // hiçbir imza artık geçerli sayılmaz.
        let mut burn_proposal = mint_proposal.clone();
        burn_proposal.tx_type = BridgeTxType::Burn;
        assert_eq!(
            bridge.count_valid_authority_signatures(&burn_proposal),
            0,
            "mint signatures must NOT be valid on a burn proposal"
        );
    }

    /// 🛡️ FAZ4.1: Her imzanın kendi `timestamp` alanı imza kapsamında. Bir
    /// saldırgan timestamp'i imzayı yeniden atmadan değiştirirse imza geçersiz olur.
    #[test]
    fn signature_is_bound_to_its_own_timestamp() {
        use ed25519_dalek::Signer;
        let bridge = BridgeManager::default_bridge_manager(CHAIN_ID);
        let now = current_time_ms();
        let sig_ts = (now / 1000) as u64;

        let mut proposal = BridgeProposal {
            proposal_id: [0x22; 32],
            tx_type: BridgeTxType::Mint,
            amount: 500 * TOKEN_DECIMAL,
            recipient: "0x0000000000000000000000000000000000000009".to_string(),
            source_chain: "Ethereum".to_string(),
            source_tx_hash: "0xtsbind".to_string(),
            timestamp: sig_ts,
            signatures: Vec::new(),
            executed: false,
            nonce: 2,
            auto_swap: false,
            amount_out_min: 0,
            claim_vouchers: Vec::new(),
        };
        let message = BridgeManager::create_signing_message(&proposal, bridge.chain_id());
        let bound = BridgeManager::bind_timestamp_to_message(&message, sig_ts);
        let key = &create_default_bridge_signers()[0];
        proposal.signatures.push(BridgeSignature {
            authority: BridgeManager::derive_address_from_public_key(
                &key.verifying_key().to_bytes(),
            ),
            signature: key.sign(&bound).to_bytes().to_vec(),
            public_key: key.verifying_key().to_bytes().to_vec(),
            timestamp: sig_ts,
        });
        assert_eq!(bridge.count_valid_authority_signatures(&proposal), 1);

        // Timestamp'i kurcala (imza aynı) → doğrulama başarısız.
        proposal.signatures[0].timestamp = sig_ts + 1;
        assert_eq!(
            bridge.count_valid_authority_signatures(&proposal),
            0,
            "tampered signature timestamp must invalidate the signature"
        );
    }

    #[test]
    fn test_daily_mint_limit() {
        let authorities = create_test_authorities();
        let mut bridge = BridgeManager::new(authorities, 3, CHAIN_ID);

        // Try to mint more than daily limit
        let now = current_time_ms();
        let state = test_state();
        let result = bridge.create_proposal(
            BridgeTxType::Mint,
            11_000_000 * TOKEN_DECIMAL, // Over 10M limit
            "zcxRECIPIENT_00000000000000000000001".to_string(),
            "Ethereum".to_string(),
            "0x123abc".to_string(),
            (now / 1000) as u64,
            false,
            0,
            now,
            state.as_ref(),
        );

        assert!(result.is_err());
    }

    /// FAZ1: default signer'larla (seed 1..count) bir öneriye eşik imzayı ekler.
    fn sign_with_defaults(bridge: &mut BridgeManager, proposal_id: &Hash, count: usize, now: u128) {
        use ed25519_dalek::Signer;
        let proposal = bridge.get_proposal(proposal_id).unwrap().clone();
        let message = BridgeManager::create_signing_message(&proposal, bridge.chain_id());
        let sig_ts = (now / 1000) as u64;
        let bound = BridgeManager::bind_timestamp_to_message(&message, sig_ts);
        let keys = create_default_bridge_signers();
        for key in keys.iter().take(count) {
            let signature = key.sign(&bound).to_bytes().to_vec();
            let authority =
                BridgeManager::derive_address_from_public_key(&key.verifying_key().to_bytes());
            let public_key = key.verifying_key().to_bytes().to_vec();
            bridge
                .sign_proposal(proposal_id, authority, signature, public_key, sig_ts, now)
                .unwrap();
        }
    }

    #[test]
    fn duplicate_deposit_returns_the_same_proposal_id_idempotently() {
        // FAZ1: aynı (source_chain, source_tx_hash) için ikinci create → AYNI id,
        // tek öneri (çift-mint kaynağı kapatıldı). Birden çok relayer aynı
        // Ethereum deposit'ini önerse bile tek proposal oluşur.
        let mut bridge = BridgeManager::default_bridge_manager(CHAIN_ID);
        let now = current_time_ms();
        let ts = (now / 1000) as u64;
        let state = test_state();
        let id1 = bridge
            .create_proposal(
                BridgeTxType::Mint,
                50 * TOKEN_DECIMAL,
                "0x0000000000000000000000000000000000000abc".to_string(),
                "Ethereum".to_string(),
                "0xSAME_DEPOSIT_TX".to_string(),
                ts,
                false,
                0,
                now,
                state.as_ref(),
            )
            .unwrap();
        let id2 = bridge
            .create_proposal(
                BridgeTxType::Mint,
                50 * TOKEN_DECIMAL,
                "0x0000000000000000000000000000000000000abc".to_string(),
                "Ethereum".to_string(),
                "0xSAME_DEPOSIT_TX".to_string(),
                ts,
                false,
                0,
                now,
                state.as_ref(),
            )
            .unwrap();
        assert_eq!(id1, id2, "aynı deposit için aynı proposal_id dönmeli");
        assert_eq!(bridge.get_pending_proposals().len(), 1);
    }

    #[test]
    fn daily_mint_limit_is_enforced_at_execution_not_just_creation() {
        // TOCTOU: günlük limit 60'a düşürülür (per-tx tavan 100'ün altında kalsın);
        // iki 40'lık öneri oluşturma anında geçer, ilki basılır, ikincisi
        // yürütme anında (80 > 60) reddedilmeli.
        let mut bridge = BridgeManager::default_bridge_manager(CHAIN_ID); // 2-of-3
        bridge.daily_mint_limit = 60 * TOKEN_DECIMAL;
        let now = current_time_ms();
        let ts = (now / 1000) as u64;
        let state = test_state();
        let id1 = bridge
            .create_proposal(
                BridgeTxType::Mint,
                40 * TOKEN_DECIMAL,
                "0x0000000000000000000000000000000000000001".to_string(),
                "Ethereum".to_string(),
                "0xdeposit_1".to_string(),
                ts,
                false,
                0,
                now,
                state.as_ref(),
            )
            .unwrap();
        let id2 = bridge
            .create_proposal(
                BridgeTxType::Mint,
                40 * TOKEN_DECIMAL,
                "0x0000000000000000000000000000000000000002".to_string(),
                "Ethereum".to_string(),
                "0xdeposit_2".to_string(),
                ts,
                false,
                0,
                now,
                state.as_ref(),
            )
            .unwrap();
        sign_with_defaults(&mut bridge, &id1, 2, now);
        sign_with_defaults(&mut bridge, &id2, 2, now);

        // Zaman kilidini (24s) geçmiş bir yürütme anı.
        let future = now + (24 * 60 * 60 + 10) * 1000;
        assert!(bridge
            .execute_proposal(&id1, future, state.as_ref())
            .is_ok());
        let second = bridge.execute_proposal(&id2, future, state.as_ref());
        assert!(second.is_err(), "günlük limit yürütme anında zorlanmalı");
    }

    /// 🛡️ Regresyon: takvim günü kovası UTC gece yarısı sınırında tavanın 2 katına
    /// izin verirdi; kayan pencerede 1 sn arayla ikinci mint REDDEDİLMELİ.
    #[test]
    fn daily_mint_limit_is_a_real_sliding_window_not_a_calendar_day_bucket() {
        let state = test_state();
        let daily_mint_limit = 10_000_000 * TOKEN_DECIMAL;

        // Bir "günün" son saniyesi: ts=86_399 (day=0'ın son saniyesi).
        let last_second_of_day_0 = 86_399u64;
        BridgeManager::check_and_record_daily_mint(
            state.as_ref(),
            daily_mint_limit,
            last_second_of_day_0,
            daily_mint_limit,
        )
        .expect("gün 0'ın tavaninin tamami gün 0 icinde basilabilmeli");

        // Yalnizca 1 saniye sonra (ts=86_400, ESKİ kodda day=1, YENİ takvim
        // günü, sayaç sifirlanirdi). Kayan pencerede bu, HALA ayni 86400
        // saniyelik penceredeki ikinci bir mint, REDDEDİLMELİ.
        let first_second_of_day_1 = 86_400u64;
        let result = BridgeManager::check_and_record_daily_mint(
            state.as_ref(),
            daily_mint_limit,
            first_second_of_day_1,
            daily_mint_limit,
        );
        assert!(
            result.is_err(),
            "KRİTİK REGRESYON: takvim-günü sınırını 1 saniye geçmek günlük tavanı \
             2 katına çıkarmamalı - kayan pencere bunu reddetmeliydi"
        );

        // Ama pencere GERÇEKTEN kayıyor: tam 86.400 saniye sonra (ilk mint
        // artık pencerenin DIŞINDA), tavanın tamamı tekrar kullanılabilmeli.
        let a_full_window_later = last_second_of_day_0 + 86_400 + 1;
        BridgeManager::check_and_record_daily_mint(
            state.as_ref(),
            daily_mint_limit,
            a_full_window_later,
            daily_mint_limit,
        )
        .expect("ilk mint tam 86400 saniye sonra pencereden dusmus olmali");
    }

    /// Kayan pencerenin GERÇEKTEN kayan olduğunu (yalnızca sıfırlanmadığını)
    /// kanıtlar: küçük parçalar halinde tavana ulaşılıp REDDEDİLDİKTEN sonra,
    /// en eski parça pencereden düşünce tam o kadarlık yeni yer açılmalı.
    #[test]
    fn daily_mint_limit_frees_up_exactly_as_old_entries_leave_the_window() {
        let state = test_state();
        let daily_mint_limit = 1_000 * TOKEN_DECIMAL;

        BridgeManager::check_and_record_daily_mint(
            state.as_ref(),
            600 * TOKEN_DECIMAL,
            1_000,
            daily_mint_limit,
        )
        .unwrap();
        BridgeManager::check_and_record_daily_mint(
            state.as_ref(),
            400 * TOKEN_DECIMAL,
            2_000,
            daily_mint_limit,
        )
        .unwrap();
        // Tavan dolu (1.000/1.000), ufak bir mint bile reddedilmeli.
        assert!(BridgeManager::check_and_record_daily_mint(
            state.as_ref(),
            1,
            3_000,
            daily_mint_limit
        )
        .is_err());

        // İlk girdi (600, ts=1000) pencereden düşsün: 1000+86400+1 = 87401.
        let after_first_entry_expires = 1_000 + 86_400 + 1;
        // Hâlâ pencerede olan ikinci girdi (400) + tam 600'lük yeni bir mint
        // = 1.000, tavanı AŞMAMALI (600 dustu, tam 600'luk yer acildi).
        BridgeManager::check_and_record_daily_mint(
            state.as_ref(),
            600 * TOKEN_DECIMAL,
            after_first_entry_expires,
            daily_mint_limit,
        )
        .expect("ilk girdi dustukten sonra tam yerine denk gelen miktar gecmeli");
    }

    #[test]
    fn test_timestamp_validation() {
        let authorities = create_test_authorities();
        let mut bridge = BridgeManager::new(authorities, 3, CHAIN_ID);

        let now = current_time_ms();
        let current_time = (now / 1000) as u64;
        let state = test_state();

        // Too old timestamp (2 hours ago)
        let result = bridge.create_proposal(
            BridgeTxType::Mint,
            1000 * TOKEN_DECIMAL,
            "zcxRECIPIENT_00000000000000000000001".to_string(),
            "Ethereum".to_string(),
            "0x123abc".to_string(),
            current_time - 7200,
            false,
            0,
            now,
            state.as_ref(),
        );
        assert!(result.is_err());

        // Too far in future (10 minutes)
        let result = bridge.create_proposal(
            BridgeTxType::Mint,
            1000 * TOKEN_DECIMAL,
            "zcxRECIPIENT_00000000000000000000001".to_string(),
            "Ethereum".to_string(),
            "0x456def".to_string(),
            current_time + 600,
            false,
            0,
            now,
            state.as_ref(),
        );
        assert!(result.is_err());
    }

    /// 🚨 Eski disk verisiyle açılış patlamamalı; küme ayrı anahtarda, yoksa boş başlar.
    #[test]
    fn loading_a_chain_written_before_this_feature_still_works() {
        let state = test_state();
        let authorities = create_test_authorities();
        let now = current_time_ms();

        // Yalnızca META yaz, `processed_sources` anahtarı HİÇ oluşturulmasın.
        // (Eski bir düğümün diskte bıraktığı durumun aynısı.)
        let legacy = BridgeManagerMeta {
            daily_minted: 42,
            last_reset: (now / 1000) as u64,
            nonce_counter: 7,
        };
        let mut account = AccountState::default();
        account.contract_code = bincode::serialize(&legacy).unwrap();
        state
            .set_account(&BridgeManager::meta_key(), account)
            .unwrap();

        let manager = BridgeManager::load_from_state(state.as_ref(), authorities, 3, CHAIN_ID)
            .expect("eski disk verisi olan zincir ACILAMADI - yukseltme dugumu bricler");

        assert_eq!(manager.daily_minted, 42, "eski meta hala okunabilmeli");
        assert!(
            !manager
                .is_source_processed("Ethereum", "0xanything", state.as_ref())
                .unwrap(),
            "kume bos baslamali"
        );
    }

    // ITEM 4: processed_sources O(1) refactor, tek-anahtar varlık kontrolü +
    // tek-blob eski verinin (item-4-öncesi) tek-seferlik geriye-doldurulması.

    #[test]
    fn is_source_processed_is_false_for_unknown_source_and_true_after_mark() {
        let state = test_state();
        let manager = BridgeManager::default_bridge_manager(CHAIN_ID);
        assert!(!manager
            .is_source_processed("Ethereum", "0xnever_seen", state.as_ref())
            .unwrap());

        manager
            .mark_source_processed("Ethereum", "0xnever_seen", state.as_ref())
            .unwrap();
        assert!(manager
            .is_source_processed("Ethereum", "0xnever_seen", state.as_ref())
            .unwrap());
        // Küçük/büyük harf duyarsız olmalı, `source_key` her ikisini de küçük harfe indiriyor.
        assert!(manager
            .is_source_processed("ETHEREUM", "0xNEVER_SEEN", state.as_ref())
            .unwrap());
    }

    #[test]
    fn create_proposal_rejects_second_proposal_for_same_source_via_state_check() {
        // Bellek içi haritaya değil O(1) state tabanlı kontrole odaklanır: FARKLI
        // manager örneği bile aynı state'i paylaşıyorsa işlenmiş kaynağı reddetmeli.
        let state = test_state();
        let first_manager = BridgeManager::default_bridge_manager(CHAIN_ID);
        first_manager
            .mark_source_processed("Ethereum", "0xalready_done", state.as_ref())
            .unwrap();

        let now = current_time_ms();
        let mut second_manager = BridgeManager::default_bridge_manager(CHAIN_ID);
        let result = second_manager.create_proposal(
            BridgeTxType::Mint,
            TOKEN_DECIMAL,
            "0x0000000000000000000000000000000000000abc".to_string(),
            "Ethereum".to_string(),
            "0xalready_done".to_string(),
            (now / 1000) as u64,
            false,
            0,
            now,
            state.as_ref(),
        );
        assert!(
            result.is_err(),
            "state'te zaten işlenmiş olarak işaretli bir kaynak için yeni bir öneri oluşturulmamalı"
        );
    }

    #[test]
    fn mark_source_processed_and_is_source_processed_round_trip_through_real_state() {
        // `MemoryStorage` yerine gerçek `StateDbManager` üzerinden, O(1) nokta
        // okuma/yazma semantiğinin gerçek State implementasyonuna karşı da
        // doğru çalıştığını doğrular.
        let storage = Arc::new(MemoryStorage::default());
        let state: Arc<dyn State> = Arc::new(StateDbManager::new(storage));
        let manager = BridgeManager::default_bridge_manager(CHAIN_ID);

        assert!(!manager
            .is_source_processed("Polygon", "0xabc", state.as_ref())
            .unwrap());
        manager
            .mark_source_processed("Polygon", "0xabc", state.as_ref())
            .unwrap();
        assert!(manager
            .is_source_processed("Polygon", "0xabc", state.as_ref())
            .unwrap());

        // Farklı bir (chain, hash) çifti hâlâ işlenmemiş olmalı.
        assert!(!manager
            .is_source_processed("Polygon", "0xdef", state.as_ref())
            .unwrap());
    }

    #[test]
    fn legacy_processed_sources_blob_is_fanned_out_into_individual_keys_on_first_load() {
        let state = test_state();
        let authorities = create_test_authorities();

        // item-4-öncesi tek-blob formatını elle yaz (eski `persist_meta`'nın
        // ürettiği ile AYNI şekil, sıralanmış `Vec<String>`, `source_key`
        // çıktısı formatında: "{chain}|{hash}", küçük harfe indirilmiş).
        let legacy_sources = vec![
            "ethereum|0xfirst".to_string(),
            "ethereum|0xsecond".to_string(),
        ];
        let mut legacy_account = AccountState::default();
        legacy_account.contract_code = bincode::serialize(&legacy_sources).unwrap();
        state
            .set_account(&"BridgeProcessedSources".to_string(), legacy_account)
            .unwrap();

        let manager = BridgeManager::load_from_state(state.as_ref(), authorities, 3, CHAIN_ID)
            .expect("eski tek-blob formatlı processed_sources ile açılış başarısız olmamalı");

        // Fan-out sonrası her iki eski kayıt da yeni O(1) anahtar şemasından okunabilmeli.
        assert!(manager
            .is_source_processed("Ethereum", "0xfirst", state.as_ref())
            .unwrap());
        assert!(manager
            .is_source_processed("Ethereum", "0xsecond", state.as_ref())
            .unwrap());
        // Hiç fan-out edilmemiş bir kaynak hâlâ işlenmemiş olmalı.
        assert!(!manager
            .is_source_processed("Ethereum", "0xthird", state.as_ref())
            .unwrap());

        // Yeni O(1) anahtarlar gerçekten diskte var (sadece bellek-içi değil).
        assert!(state
            .get_account(&"BridgeProcessedSource_ethereum|0xfirst".to_string())
            .unwrap()
            .is_some());
    }

    #[test]
    fn legacy_fan_out_migration_is_idempotent_and_runs_only_once() {
        let state = test_state();
        let authorities = create_test_authorities();

        let legacy_sources = vec!["ethereum|0xonce".to_string()];
        let mut legacy_account = AccountState::default();
        legacy_account.contract_code = bincode::serialize(&legacy_sources).unwrap();
        state
            .set_account(&"BridgeProcessedSources".to_string(), legacy_account)
            .unwrap();

        // İlk açılış: fan-out çalışır, sentinel anahtar yazılır.
        let _manager1 =
            BridgeManager::load_from_state(state.as_ref(), authorities.clone(), 3, CHAIN_ID)
                .unwrap();
        let migration_account_first = state
            .get_account(&"__MIGRATION_BridgeProcessedSourcesFanOut__".to_string())
            .unwrap()
            .expect("ilk açılıştan sonra migration sentinel'i yazılmış olmalı");
        let record: zagros_types::MigrationRecord =
            bincode::deserialize(&migration_account_first.contract_code).unwrap();
        assert_eq!(record.version, 1);

        // İkinci (ve üçüncü) açılış, sentinel VARLIĞI yüzünden fan-out bloğu
        // hiç ÇALIŞMAMALI (no-op): ne panik/hata olur, ne de sonuç değişir.
        let manager2 =
            BridgeManager::load_from_state(state.as_ref(), authorities.clone(), 3, CHAIN_ID)
                .unwrap();
        assert!(manager2
            .is_source_processed("Ethereum", "0xonce", state.as_ref())
            .unwrap());
        let manager3 =
            BridgeManager::load_from_state(state.as_ref(), authorities, 3, CHAIN_ID).unwrap();
        assert!(manager3
            .is_source_processed("Ethereum", "0xonce", state.as_ref())
            .unwrap());
    }

    /// Üç alan eklenmeden önceki disk kaydını taklit eder; KASITLI olarak
    /// `BridgeProposalV0`'a referans vermez (bincode pozisyonel, aynı alan sırası
    /// aynı baytları üretir), göç uygulamasından bağımsız eski bayt.
    #[derive(Serialize)]
    struct LegacyProposalMirror {
        proposal_id: Hash,
        tx_type: BridgeTxType,
        amount: u128,
        recipient: Address,
        source_chain: String,
        source_tx_hash: String,
        timestamp: u64,
        // Boş bir Vec her zaman aynı (yalnızca sıfır-uzunluk öneki içeren)
        // baytlara serileşir, gerçek `Vec<BridgeSignature>` yerine (o tipin
        // iç yapısına bağımlı olmadan) bu yer tutucu güvenle kullanılabilir.
        signatures: Vec<u8>,
        executed: bool,
        nonce: u64,
    }

    fn legacy_proposal_bytes(proposal_id: Hash, amount: u128, recipient: &str) -> Vec<u8> {
        bincode::serialize(&LegacyProposalMirror {
            proposal_id,
            tx_type: BridgeTxType::Mint,
            amount,
            recipient: recipient.to_string(),
            source_chain: "Ethereum".to_string(),
            source_tx_hash: "0xdeadbeef".to_string(),
            timestamp: 1_000,
            signatures: vec![],
            executed: false,
            nonce: 3,
        })
        .unwrap()
    }

    /// 🛡️ V0 fallback/migration: `#[serde(default)]` tek başına işe yaramadığı
    /// önce kanıtlanır, sonra göçün gerçekten çalıştığı.
    #[test]
    fn old_bridge_proposal_without_auto_swap_fields_still_deserializes() {
        let proposal_id = [7u8; 32];
        let legacy_bytes = legacy_proposal_bytes(
            proposal_id,
            5 * TOKEN_DECIMAL,
            "0x4f0b2551e2c46292de5e32941c3277541e9e4568",
        );

        // Güncel şekille DOĞRUDAN (migration olmadan) deserialize etmeye
        // çalışmak başarısız OLMALI, aksi halde bu test hiçbir şey kanıtlamaz.
        assert!(
            bincode::deserialize::<BridgeProposal>(&legacy_bytes).is_err(),
            "bu test eski baytların GÜNCEL şekille zaten uyumlu olmadığını varsayıyor"
        );

        let migrated = BridgeProposal::deserialize_with_migration(&legacy_bytes)
            .expect("eski (auto_swap/amount_out_min/claim_vouchers olmayan) proposal okunabilmeli");

        assert_eq!(migrated.proposal_id, proposal_id);
        assert_eq!(migrated.amount, 5 * TOKEN_DECIMAL);
        assert_eq!(migrated.nonce, 3);
        assert!(!migrated.auto_swap);
        assert_eq!(migrated.amount_out_min, 0);
        assert!(migrated.claim_vouchers.is_empty());
    }

    /// Aynı senaryo ama gerçek genel API'den (`load_proposal_from_state`),
    /// RPC/CLI'nin ve `load_from_state`'in GERÇEKTEN çağırdığı yol.
    #[test]
    fn load_proposal_from_state_reads_a_pre_auto_swap_proposal() {
        let state = test_state();
        let proposal_id = [9u8; 32];
        let legacy_bytes = legacy_proposal_bytes(
            proposal_id,
            3 * TOKEN_DECIMAL,
            "0x4f0b2551e2c46292de5e32941c3277541e9e4568",
        );
        let mut account = AccountState::default();
        account.contract_code = legacy_bytes;
        state
            .set_account(&BridgeManager::proposal_state_key(&proposal_id), account)
            .unwrap();

        let proposal = BridgeManager::load_proposal_from_state(state.as_ref(), &proposal_id)
            .expect("okuma hata vermemeli")
            .expect("proposal bulunmali");
        assert_eq!(proposal.amount, 3 * TOKEN_DECIMAL);
        assert!(!proposal.auto_swap);
        assert_eq!(proposal.amount_out_min, 0);
        assert!(proposal.claim_vouchers.is_empty());
    }

    /// Güncel şekille (auto_swap/amount_out_min GERÇEK, sıfır olmayan değerlerle)
    /// oluşturulmuş bir öneri migration'a hiç uğramadan (hızlı yol) doğru
    /// okunmalı, fallback eklenmesi normal işleyişi bozmamış.
    #[test]
    fn current_bridge_proposal_with_auto_swap_round_trips_without_migration() {
        let state = test_state();
        let authorities = create_test_authorities();
        let now = current_time_ms();
        let mut bridge = BridgeManager::new(authorities, 3, CHAIN_ID);
        let proposal_id = bridge
            .create_proposal(
                BridgeTxType::Mint,
                7 * TOKEN_DECIMAL,
                "0x4f0b2551e2c46292de5e32941c3277541e9e4568".to_string(),
                "Ethereum".to_string(),
                "0xabc123".to_string(),
                (now / 1000) as u64,
                true,
                1_000,
                now,
                state.as_ref(),
            )
            .unwrap();
        bridge
            .persist_proposal(state.as_ref(), &proposal_id)
            .unwrap();

        let reloaded = BridgeManager::load_proposal_from_state(state.as_ref(), &proposal_id)
            .unwrap()
            .expect("guncel formatli proposal okunabilmeli");
        assert!(reloaded.auto_swap);
        assert_eq!(reloaded.amount_out_min, 1_000);
    }

    /// 🛡️ EN KRİTİK: gerçek restart yolu (`load_from_state`) eski formatlı
    /// BEKLEYEN öneride panik atmamalı; tek eski öneri tüm düğümün açılışını engellerdi.
    #[test]
    fn load_from_state_restarts_cleanly_with_a_pending_legacy_proposal() {
        let state = test_state();
        let authorities = create_test_authorities();
        let proposal_id = [11u8; 32];
        let legacy_bytes = legacy_proposal_bytes(
            proposal_id,
            2 * TOKEN_DECIMAL,
            "0x4f0b2551e2c46292de5e32941c3277541e9e4568",
        );

        let mut proposal_account = AccountState::default();
        proposal_account.contract_code = legacy_bytes;
        state
            .set_account(
                &BridgeManager::proposal_state_key(&proposal_id),
                proposal_account,
            )
            .unwrap();

        // Bekleyen indekste de olmalı, `load_from_state` yalnızca buradaki
        // ID'leri tarayıp tek tek yükler (eski bir düğümün diskte bıraktığı
        // durumun aynısı).
        let mut index_account = AccountState::default();
        index_account.contract_code = bincode::serialize(&vec![proposal_id]).unwrap();
        state
            .set_account(&BridgeManager::pending_index_key(), index_account)
            .unwrap();

        let manager = BridgeManager::load_from_state(state.as_ref(), authorities, 3, CHAIN_ID)
            .expect("eski formatli bekleyen bir oneriyle acilis PANIKLEMEMELI/HATA VERMEMELI");

        let loaded = manager
            .get_proposal(&proposal_id)
            .expect("eski oneri bellekte olmali");
        assert_eq!(loaded.amount, 2 * TOKEN_DECIMAL);
        assert!(!loaded.auto_swap);
        assert_eq!(loaded.amount_out_min, 0);
        assert!(loaded.claim_vouchers.is_empty());
    }

    #[test]
    fn a_deposit_already_credited_cannot_be_minted_again_after_restart() {
        let state = test_state();
        let now = current_time_ms();
        let authorities = create_test_authorities();

        // --- 1. tur: yatırma normal şekilde işlenir ve YÜRÜTÜLÜR.
        let mut bridge = BridgeManager::new(authorities.clone(), 3, CHAIN_ID);
        let proposal_id = bridge
            .create_proposal(
                BridgeTxType::Mint,
                5 * TOKEN_DECIMAL,
                "0x4f0b2551e2c46292de5e32941c3277541e9e4568".to_string(),
                "Ethereum".to_string(),
                "0xb17479a1".to_string(),
                (now / 1000) as u64,
                false,
                0,
                now,
                state.as_ref(),
            )
            .unwrap();
        use ed25519_dalek::Signer;
        let message = BridgeManager::create_signing_message(
            bridge.get_proposal(&proposal_id).unwrap(),
            bridge.chain_id(),
        );
        let sig_ts = (now / 1000) as u64;
        let bound = BridgeManager::bind_timestamp_to_message(&message, sig_ts);
        for i in 1..=3u8 {
            let mut seed = [0u8; 32];
            seed[0] = i;
            let signing_key = SigningKey::from_bytes(&seed);
            // `create_test_authorities` yetkilileri bu adreslerle kaydediyor.
            let authority_address = format!("zcxAUTH{}_00000000000000000000000000{}", i, i);
            bridge
                .sign_proposal(
                    &proposal_id,
                    authority_address,
                    signing_key.sign(&bound).to_bytes().to_vec(),
                    signing_key.verifying_key().to_bytes().to_vec(),
                    sig_ts,
                    now,
                )
                .unwrap();
        }
        // Zaman kilidini geçmiş say.
        let after_timelock = now + (bridge.timelock_period() as u128 + 1) * 1000;
        bridge
            .execute_proposal(&proposal_id, after_timelock, state.as_ref())
            .unwrap();
        bridge
            .persist_proposal(state.as_ref(), &proposal_id)
            .unwrap();
        bridge.persist_meta(state.as_ref()).unwrap();

        // --- Düğüm yeniden başlar: bellek sıfırlanır, disk kalır.
        let mut reloaded =
            BridgeManager::load_from_state(state.as_ref(), authorities, 3, CHAIN_ID).unwrap();

        // Yürütülmüş öneri bekleyen indekste OLMADIĞI için bellekte yok,
        // eski dedup'ın körleştiği nokta tam olarak burasıydı.
        assert!(reloaded.get_proposal(&proposal_id).is_none());

        // --- İmleci geride kalmış haberci AYNI yatırmayı tekrar önerir.
        let retry = reloaded.create_proposal(
            BridgeTxType::Mint,
            5 * TOKEN_DECIMAL,
            "0x4f0b2551e2c46292de5e32941c3277541e9e4568".to_string(),
            "Ethereum".to_string(),
            "0xb17479a1".to_string(),
            (now / 1000) as u64,
            false,
            0,
            now,
            state.as_ref(),
        );

        assert!(
            retry.is_err(),
            "zaten kredilendirilmis bir yatirma icin YENI oneri olusturuldu - \
             karsiliksiz ZERENYA basimina yol acar"
        );
        assert!(reloaded
            .is_source_processed("Ethereum", "0xb17479a1", state.as_ref())
            .unwrap());
    }

    // ITEM 5: Bridge proposal archive

    #[test]
    fn mark_executed_in_state_moves_proposal_to_archive_key_and_empties_active_key() {
        let state = test_state();
        let authorities = create_test_authorities();
        let now = current_time_ms();

        let mut bridge = BridgeManager::new(authorities, 3, CHAIN_ID);
        let proposal_id = bridge
            .create_proposal(
                BridgeTxType::Mint,
                4 * TOKEN_DECIMAL,
                "0x4f0b2551e2c46292de5e32941c3277541e9e4568".to_string(),
                "Ethereum".to_string(),
                "0xarchive_me".to_string(),
                (now / 1000) as u64,
                false,
                0,
                now,
                state.as_ref(),
            )
            .unwrap();
        bridge
            .persist_proposal(state.as_ref(), &proposal_id)
            .unwrap();

        BridgeManager::mark_executed_in_state(state.as_ref(), &proposal_id).unwrap();

        // Aktif anahtar mantıksal olarak boşaltılmış olmalı (var ama boş,
        // kod tabanının geri kalanının kullandığı "bulunamadı" idiomu).
        let active_account = state
            .get_account(&BridgeManager::proposal_state_key(&proposal_id))
            .unwrap()
            .expect("aktif anahtarın kendisi hâlâ var olmalı (sadece boşaltılmış)");
        assert!(
            active_account.contract_code.is_empty(),
            "yürütülmüş bir öneri aktif anahtarda hâlâ tam veri içeriyor"
        );
        assert!(
            BridgeManager::load_proposal_from_state(state.as_ref(), &proposal_id)
                .unwrap()
                .is_none(),
            "aktif-anahtar okuyucusu artık bu öneriyi 'bulunamadı' olarak görmeli"
        );

        // Arşiv anahtarında tam kayıt olmalı.
        let archived =
            BridgeManager::load_archived_proposal_from_state(state.as_ref(), &proposal_id)
                .unwrap()
                .expect("arşivlenmiş öneri okunabilmeli");
        assert_eq!(archived.amount, 4 * TOKEN_DECIMAL);
        assert!(archived.executed);
    }

    #[test]
    fn load_proposal_from_state_returns_none_for_an_archived_proposal() {
        let state = test_state();
        let authorities = create_test_authorities();
        let now = current_time_ms();
        let mut bridge = BridgeManager::new(authorities, 3, CHAIN_ID);
        let proposal_id = bridge
            .create_proposal(
                BridgeTxType::Mint,
                TOKEN_DECIMAL,
                "0x4f0b2551e2c46292de5e32941c3277541e9e4568".to_string(),
                "Ethereum".to_string(),
                "0xnone_after_archive".to_string(),
                (now / 1000) as u64,
                false,
                0,
                now,
                state.as_ref(),
            )
            .unwrap();
        bridge
            .persist_proposal(state.as_ref(), &proposal_id)
            .unwrap();
        assert!(
            BridgeManager::load_proposal_from_state(state.as_ref(), &proposal_id)
                .unwrap()
                .is_some(),
            "yürütülmeden önce aktif anahtardan okunabilmeli"
        );

        BridgeManager::mark_executed_in_state(state.as_ref(), &proposal_id).unwrap();

        assert!(
            BridgeManager::load_proposal_from_state(state.as_ref(), &proposal_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn load_archived_proposal_from_state_returns_the_full_executed_proposal() {
        let state = test_state();
        // Arşivlenmemiş bir id için None dönmeli.
        assert!(
            BridgeManager::load_archived_proposal_from_state(state.as_ref(), &[123u8; 32])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn get_pending_proposals_prune_ids_not_in_removes_executed_entries_only() {
        let state = test_state();
        let authorities = create_test_authorities();
        let now = current_time_ms();
        let mut bridge = BridgeManager::new(authorities, 3, CHAIN_ID);

        let executed_id = bridge
            .create_proposal(
                BridgeTxType::Mint,
                TOKEN_DECIMAL,
                "0x4f0b2551e2c46292de5e32941c3277541e9e4568".to_string(),
                "Ethereum".to_string(),
                "0xwill_be_executed".to_string(),
                (now / 1000) as u64,
                false,
                0,
                now,
                state.as_ref(),
            )
            .unwrap();
        let still_pending_id = bridge
            .create_proposal(
                BridgeTxType::Mint,
                TOKEN_DECIMAL,
                "0x4f0b2551e2c46292de5e32941c3277541e9e4568".to_string(),
                "Ethereum".to_string(),
                "0xstill_pending".to_string(),
                (now / 1000) as u64,
                false,
                0,
                now,
                state.as_ref(),
            )
            .unwrap();
        bridge
            .persist_proposal(state.as_ref(), &executed_id)
            .unwrap();
        bridge
            .persist_proposal(state.as_ref(), &still_pending_id)
            .unwrap();
        assert_eq!(bridge.get_pending_proposals().len(), 2);

        // `executed_id` başka bir yoldan (gerçek üretim yolu, canlı `bridge`
        // instance'ına HİÇ dokunmadan) yürütülüp arşivlendi.
        BridgeManager::mark_executed_in_state(state.as_ref(), &executed_id).unwrap();

        // Mutabakat adımı (CLI'nin her turda yaptığı): state'in taze bekleyen
        // listesiyle buda.
        bridge.prune_ids_not_in(&[still_pending_id]);

        let remaining: Vec<Hash> = bridge
            .get_pending_proposals()
            .iter()
            .map(|p| p.proposal_id)
            .collect();
        assert_eq!(remaining, vec![still_pending_id]);
    }

    #[test]
    fn a_proposal_reaches_disk_without_waiting_for_a_block() {
        // Storage'a DOĞRUDAN erişebilmek için elimizde tutuyoruz, testin tüm
        // amacı cache'i atlayıp alt katmana bakmak.
        let storage = Arc::new(MemoryStorage::default());
        let state = Arc::new(StateDbManager::new(storage.clone()));
        let now = current_time_ms();

        let mut bridge = BridgeManager::new(create_test_authorities(), 3, CHAIN_ID);
        let proposal_id = bridge
            .create_proposal(
                BridgeTxType::Burn,
                5 * TOKEN_DECIMAL,
                "0x4f0b2551e2c46292de5e32941c3277541e9e4568".to_string(),
                "Ethereum".to_string(),
                "0xbdc232c4".to_string(),
                (now / 1000) as u64,
                false,
                0,
                now,
                state.as_ref(),
            )
            .unwrap();

        bridge
            .persist_proposal(state.as_ref(), &proposal_id)
            .unwrap();

        // Hiçbir blok işlenmedi. Yine de DİSKTE olmalı.
        let key = BridgeManager::proposal_state_key(&proposal_id);
        let on_disk = storage.get(key.as_bytes()).unwrap();
        assert!(
            on_disk.is_some(),
            "oneri diske yazilmadi - dugum yeniden baslarsa KAYBOLUR ve \
             kullanicinin yakilmis ZERENYA'sı talep edilemez hale gelir"
        );
    }

    #[test]
    fn persisted_proposal_and_counters_survive_manager_reconstruction() {
        let state = test_state();
        let authorities = create_test_authorities();
        let now = current_time_ms();

        let mut bridge = BridgeManager::new(authorities.clone(), 3, CHAIN_ID);
        let proposal_id = bridge
            .create_proposal(
                BridgeTxType::Mint,
                50 * TOKEN_DECIMAL,
                "zcxRECIPIENT_00000000000000000000001".to_string(),
                "Ethereum".to_string(),
                "0xrestart_test".to_string(),
                (now / 1000) as u64,
                false,
                0,
                now,
                state.as_ref(),
            )
            .unwrap();
        bridge
            .persist_proposal(state.as_ref(), &proposal_id)
            .unwrap();
        bridge.persist_meta(state.as_ref()).unwrap();

        // "Restart": bir daha, sıfırdan bir BridgeManager inşa et, yetkililer
        // her zamanki gibi config'den (burada aynı test yetkilileri) gelir,
        // ama sayaçlar/öneriler diskten geri yüklenmeli.
        let reloaded =
            BridgeManager::load_from_state(state.as_ref(), authorities, 3, CHAIN_ID).unwrap();

        let reloaded_proposal = reloaded.get_proposal(&proposal_id).unwrap();
        assert_eq!(reloaded_proposal.amount, 50 * TOKEN_DECIMAL);
        assert_eq!(reloaded_proposal.source_tx_hash, "0xrestart_test");
        assert_eq!(reloaded.nonce_counter, bridge.nonce_counter);

        // Nonce sayacı diskten doğru geri yüklendiği için yeni bir öneri
        // eskisiyle çakışmamalı (proposal_id nonce'a bağlı olarak üretiliyor).
        let mut reloaded = reloaded;
        let second_id = reloaded
            .create_proposal(
                BridgeTxType::Mint,
                40 * TOKEN_DECIMAL,
                "zcxRECIPIENT_00000000000000000000002".to_string(),
                "Ethereum".to_string(),
                "0xsecond".to_string(),
                (now / 1000) as u64,
                false,
                0,
                now,
                state.as_ref(),
            )
            .unwrap();
        assert_ne!(proposal_id, second_id);
    }

    #[test]
    fn persisted_signatures_and_can_execute_survive_reload() {
        let state = test_state();
        // `default_authorities()` adresi pubkey'den türetir (test imzasıyla uyumlu);
        // `create_test_authorities()` gerçek anahtara karşılık gelmeyen sahte adresler kullanır.
        let authorities = BridgeManager::default_authorities();
        let now = current_time_ms();

        let mut bridge = BridgeManager::new(authorities.clone(), 3, CHAIN_ID);
        let proposal_id = bridge
            .create_proposal(
                BridgeTxType::Mint,
                50 * TOKEN_DECIMAL,
                "zcxRECIPIENT_00000000000000000000003".to_string(),
                "Ethereum".to_string(),
                "0xsig_persist".to_string(),
                (now / 1000) as u64,
                false,
                0,
                now,
                state.as_ref(),
            )
            .unwrap();

        use ed25519_dalek::Signer;
        let message = BridgeManager::create_signing_message(
            bridge.get_proposal(&proposal_id).unwrap(),
            bridge.chain_id(),
        );
        let sig_ts = (now / 1000) as u64;
        let bound = BridgeManager::bind_timestamp_to_message(&message, sig_ts);
        for i in 1..=3u8 {
            let mut seed = [0u8; 32];
            seed[0] = i;
            let signing_key = SigningKey::from_bytes(&seed);
            let signature = signing_key.sign(&bound).to_bytes().to_vec();
            let authority_address = BridgeManager::derive_address_from_public_key(
                &signing_key.verifying_key().to_bytes(),
            );
            bridge
                .sign_proposal(
                    &proposal_id,
                    authority_address,
                    signature,
                    signing_key.verifying_key().to_bytes().to_vec(),
                    sig_ts,
                    now,
                )
                .unwrap();
        }
        bridge
            .persist_proposal(state.as_ref(), &proposal_id)
            .unwrap();

        let reloaded =
            BridgeManager::load_from_state(state.as_ref(), authorities, 3, CHAIN_ID).unwrap();
        let reloaded_proposal = reloaded.get_proposal(&proposal_id).unwrap();
        assert_eq!(reloaded_proposal.signatures.len(), 3);

        // Zaman kilidi henüz dolmadığı için ikisinde de (orijinal ve
        // yeniden yüklenen) can_execute false olmalı, imza sayısı korunmuş
        // olsa bile.
        assert!(!bridge.can_execute(&proposal_id, now).unwrap());
        assert!(!reloaded.can_execute(&proposal_id, now).unwrap());
    }

    // 🎟️ CLAIM FİŞİ (VOUCHER) KABUL TESTLERİ

    /// Test için deterministik bir haberci secp256k1 anahtarı ve Ethereum adresi.
    fn test_relayer_key(seed: u8) -> (secp256k1::SecretKey, [u8; 20]) {
        use sha3::{Digest, Keccak256};
        let secret = secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap();
        let public = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &secret);
        let uncompressed = public.serialize_uncompressed();
        let hashed = Keccak256::digest(&uncompressed[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hashed[12..]);
        (secret, address)
    }

    fn sign_digest(secret: &secp256k1::SecretKey, digest: &[u8; 32]) -> String {
        let secp = secp256k1::Secp256k1::new();
        let message = secp256k1::Message::from_digest_slice(digest).unwrap();
        let (recovery_id, compact) = secp
            .sign_ecdsa_recoverable(&message, secret)
            .serialize_compact();
        let mut signature = [0u8; 65];
        signature[..64].copy_from_slice(&compact);
        signature[64] = 27 + recovery_id.to_i32() as u8;
        format!("0x{}", hex::encode(signature))
    }

    const TEST_GATEWAY: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
    const TEST_TOKEN: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    const TEST_RECIPIENT: &str = "0x4F0B2551e2c46292de5E32941c3277541E9e4568";
    const TEST_BURN_HASH: &str =
        "0xabababababababababababababababababababababababababababababababab";

    /// Fiş kabulü açık bir manager + içinde bir burn önerisi döner.
    fn manager_with_burn_proposal(relayers: Vec<[u8; 20]>) -> (BridgeManager, Hash) {
        let mut manager = BridgeManager::new(BridgeManager::default_authorities(), 2, 21072026)
            .with_claim_context(ClaimContext {
                chain_id: 31337,
                gateway: eip712::parse_eth_address(TEST_GATEWAY).unwrap(),
                token: eip712::parse_eth_address(TEST_TOKEN).unwrap(),
                // Testte ölçekleme kimlik olsun diye 18; 6-ondalık ölçeklemesi
                // `bridge_amount` modülünün kendi testlerinde kanıtlanıyor.
                token_decimals: 18,
                relayers,
            });
        let now = 1_700_000_000_000u128;
        let state = test_state();
        let proposal_id = manager
            .create_proposal(
                BridgeTxType::Burn,
                1_234_567,
                TEST_RECIPIENT.to_string(),
                "Ethereum".to_string(),
                TEST_BURN_HASH.to_string(),
                (now / 1000) as u64,
                false,
                0,
                now,
                state.as_ref(),
            )
            .unwrap();
        (manager, proposal_id)
    }

    fn digest_for(manager: &BridgeManager, proposal_id: &Hash) -> [u8; 32] {
        let proposal = manager.get_proposal(proposal_id).unwrap();
        eip712::claim_digest(
            31337,
            &eip712::parse_eth_address(TEST_GATEWAY).unwrap(),
            &eip712::parse_eth_address(TEST_TOKEN).unwrap(),
            &eip712::parse_eth_address(&proposal.recipient).unwrap(),
            &eip712::amount_to_be_bytes(proposal.amount),
            &eip712::parse_h256(&proposal.source_tx_hash).unwrap(),
        )
    }

    #[test]
    fn accepts_a_voucher_signed_by_a_configured_relayer() {
        let (secret, address) = test_relayer_key(11);
        let (mut manager, proposal_id) = manager_with_burn_proposal(vec![address]);
        let signature = sign_digest(&secret, &digest_for(&manager, &proposal_id));

        let signer = manager.add_claim_voucher(&proposal_id, &signature).unwrap();
        assert_eq!(signer, format!("0x{}", hex::encode(address)));
        assert_eq!(
            manager
                .get_proposal(&proposal_id)
                .unwrap()
                .claim_vouchers
                .len(),
            1
        );
    }

    /// 🚨 Yetkisiz imzacı reddedilmeli, aksi halde düğüm, zincirde kesin
    /// reddedilecek çöp fişleri saklar ve kullanıcıya işe yaramaz veri sunardı.
    #[test]
    fn rejects_a_voucher_from_an_unknown_signer() {
        let (_, known) = test_relayer_key(11);
        let (outsider_secret, _) = test_relayer_key(99);
        let (mut manager, proposal_id) = manager_with_burn_proposal(vec![known]);
        let signature = sign_digest(&outsider_secret, &digest_for(&manager, &proposal_id));

        let error = manager
            .add_claim_voucher(&proposal_id, &signature)
            .unwrap_err();
        assert!(format!("{}", error).contains("not from a configured bridge relayer"));
        assert!(manager
            .get_proposal(&proposal_id)
            .unwrap()
            .claim_vouchers
            .is_empty());
    }

    /// BAŞKA bir öneriye ait imza kabul edilmemeli (dijest önerinin verilerine bağlı).
    #[test]
    fn rejects_a_voucher_signed_for_a_different_claim() {
        let (secret, address) = test_relayer_key(11);
        let (mut manager, proposal_id) = manager_with_burn_proposal(vec![address]);

        // Tutarı değiştirilmiş bir dijest imzala.
        let mut tampered = digest_for(&manager, &proposal_id);
        tampered[0] ^= 0xff;
        let signature = sign_digest(&secret, &tampered);

        assert!(manager.add_claim_voucher(&proposal_id, &signature).is_err());
    }

    /// Bağlam yapılandırılmamışsa fiş kabulü KAPALI olmalı (fail-closed).
    #[test]
    fn rejects_vouchers_when_the_ethereum_context_is_not_configured() {
        let mut manager = BridgeManager::new(BridgeManager::default_authorities(), 2, 21072026);
        let now = 1_700_000_000_000u128;
        let state = test_state();
        let proposal_id = manager
            .create_proposal(
                BridgeTxType::Burn,
                1,
                TEST_RECIPIENT.to_string(),
                "Ethereum".to_string(),
                TEST_BURN_HASH.to_string(),
                (now / 1000) as u64,
                false,
                0,
                now,
                state.as_ref(),
            )
            .unwrap();

        let error = manager.add_claim_voucher(&proposal_id, "0x00").unwrap_err();
        assert!(format!("{}", error).contains("disabled"));
    }

    /// Aynı haberciden gelen ikinci fiş listeyi BÜYÜTMEMELİ (idempotent).
    #[test]
    fn a_relayer_cannot_inflate_the_voucher_list_by_resubmitting() {
        let (secret, address) = test_relayer_key(11);
        let (mut manager, proposal_id) = manager_with_burn_proposal(vec![address]);
        let signature = sign_digest(&secret, &digest_for(&manager, &proposal_id));

        manager.add_claim_voucher(&proposal_id, &signature).unwrap();
        manager.add_claim_voucher(&proposal_id, &signature).unwrap();

        assert_eq!(
            manager
                .get_proposal(&proposal_id)
                .unwrap()
                .claim_vouchers
                .len(),
            1
        );
    }

    /// 🔢 Ölçekleme dijeste yansımalı: 6 ondalıklı hedef token için dijest
    /// ölçeklenmiş tutarla hesaplanır; ham tutarla imzalanan fiş reddedilmeli.
    #[test]
    fn digest_uses_the_scaled_token_amount_not_the_raw_zerenya_amount() {
        let (secret, address) = test_relayer_key(11);

        let mut manager = BridgeManager::new(BridgeManager::default_authorities(), 2, 21072026)
            .with_claim_context(ClaimContext {
                chain_id: 31337,
                gateway: eip712::parse_eth_address(TEST_GATEWAY).unwrap(),
                token: eip712::parse_eth_address(TEST_TOKEN).unwrap(),
                token_decimals: 6, // varsayımsal 6 ondalıklı hedef (PAXG=18'den bilinçli farklı)
                relayers: vec![address],
            });
        let now = 1_700_000_000_000u128;
        let state = test_state();
        // 2.5 ZERENYA -> 2_500_000 birim (6 ondalıklı varsayımsal hedefte)
        let zerenya_amount = 2_500_000_000_000_000_000u128;
        let proposal_id = manager
            .create_proposal(
                BridgeTxType::Burn,
                zerenya_amount,
                TEST_RECIPIENT.to_string(),
                "Ethereum".to_string(),
                TEST_BURN_HASH.to_string(),
                (now / 1000) as u64,
                false,
                0,
                now,
                state.as_ref(),
            )
            .unwrap();

        let digest_with = |amount: u128| {
            eip712::claim_digest(
                31337,
                &eip712::parse_eth_address(TEST_GATEWAY).unwrap(),
                &eip712::parse_eth_address(TEST_TOKEN).unwrap(),
                &eip712::parse_eth_address(TEST_RECIPIENT).unwrap(),
                &eip712::amount_to_be_bytes(amount),
                &eip712::parse_h256(TEST_BURN_HASH).unwrap(),
            )
        };

        // HAM ZERENYA tutarıyla imzalanan fiş REDDEDİLMELİ.
        let raw_signature = sign_digest(&secret, &digest_with(zerenya_amount));
        assert!(manager
            .add_claim_voucher(&proposal_id, &raw_signature)
            .is_err());

        // ÖLÇEKLENMİŞ tutarla imzalanan fiş KABUL EDİLMELİ.
        let scaled_signature = sign_digest(&secret, &digest_with(2_500_000));
        assert!(manager
            .add_claim_voucher(&proposal_id, &scaled_signature)
            .is_ok());
    }

    /// Hedef varlığın 1 biriminin altındaki bir yakma için fiş ÜRETİLMEMELİ,
    /// kontrat `require(_amount > 0)` ile revert eder ve kullanıcının gas'ı
    /// boşa yanardı.
    #[test]
    fn rejects_a_burn_too_small_to_scale_to_one_token_unit() {
        let (_, address) = test_relayer_key(11);
        let mut manager = BridgeManager::new(BridgeManager::default_authorities(), 2, 21072026)
            .with_claim_context(ClaimContext {
                chain_id: 31337,
                gateway: eip712::parse_eth_address(TEST_GATEWAY).unwrap(),
                token: eip712::parse_eth_address(TEST_TOKEN).unwrap(),
                token_decimals: 6, // varsayımsal 6 ondalıklı hedef
                relayers: vec![address],
            });
        let now = 1_700_000_000_000u128;
        let state = test_state();
        let proposal_id = manager
            .create_proposal(
                BridgeTxType::Burn,
                999_999_999_999, // 1e12'nin altinda -> 0 birim
                TEST_RECIPIENT.to_string(),
                "Ethereum".to_string(),
                TEST_BURN_HASH.to_string(),
                (now / 1000) as u64,
                false,
                0,
                now,
                state.as_ref(),
            )
            .unwrap();

        let error = manager.add_claim_voucher(&proposal_id, "0x00").unwrap_err();
        assert!(format!("{}", error).contains("does not scale to a non-zero"));
    }

    /// Kodlayıcının ürettiği baytlar `swap_amount_out_min`'in beklediği düzenle
    /// (68 bayt, minimum bytes[36..68] BE) eşleşmeli; uçtan uca kanıt `lib.rs` testlerinde.
    #[test]
    fn encode_amount_out_min_payload_matches_the_expected_byte_layout() {
        let payload = BridgeManager::encode_amount_out_min_payload(1_234_567);
        assert_eq!(payload.len(), 68);
        assert!(
            payload[..36].iter().all(|b| *b == 0),
            "ilk 36 bayt kullanilmiyor, sifir olmali"
        );
        let decoded = crate::swap::swap_amount_out_min(&Transaction {
            tx_id: [0u8; 32],
            tx_type: zagros_types::TxType::BridgeMintAndSwap,
            sender: String::new(),
            amount: 0,
            receiver: String::new(),
            payload,
            signature: Vec::new(),
            timestamp: 0,
            nonce: 0,
            gas_limit: 0,
            gas_price: 0,
            chain_id: 0,
        })
        .unwrap();
        assert_eq!(decoded, 1_234_567);
    }

    // P2P follower senkronu: `collect_proposals_for_relay`/`ingest_relayed_proposals`,
    // öneri blokla taşınmazsa follower mint işlemini asla doğrulayamaz.

    /// `default_authorities()` kumesini (2-of-3) zincire yazar, artik
    /// `ingest_relayed_proposals` bu kume olmadan HICBIR SEY yazmiyor.
    fn store_default_authority_set(state: &dyn State) {
        store_bridge_authority_set(
            state,
            &OnChainBridgeAuthoritySet {
                authorities: BridgeManager::default_authorities(),
                required_signatures: 2,
            },
        )
        .unwrap();
    }

    /// `sample_bridge_proposal`in, `default_authorities()`ten `count` tanesinin
    /// GECERLI Ed25519 imzasini tasiyan hali.
    fn sample_proposal_signed_by(proposal_id: Hash, count: usize) -> BridgeProposal {
        use ed25519_dalek::{Signer, SigningKey};
        let mut proposal = sample_bridge_proposal(proposal_id, false);
        let message = BridgeManager::create_signing_message(&proposal, zagros_types::CHAIN_ID);
        let sig_ts = proposal.timestamp;
        let bound = BridgeManager::bind_timestamp_to_message(&message, sig_ts);
        for i in 1..=count as u8 {
            let mut seed = [0u8; 32];
            seed[0] = i;
            let key = SigningKey::from_bytes(&seed);
            proposal.signatures.push(BridgeSignature {
                authority: BridgeManager::derive_address_from_public_key(
                    &key.verifying_key().to_bytes(),
                ),
                signature: key.sign(&bound).to_bytes().to_vec(),
                public_key: key.verifying_key().to_bytes().to_vec(),
                timestamp: sig_ts,
            });
        }
        proposal
    }

    fn signed_sample_proposal(proposal_id: Hash) -> BridgeProposal {
        sample_proposal_signed_by(proposal_id, 2)
    }

    /// 🚨 Kısmi yerel kopya blokla gelen TAM sürümün yazılmasını engellememeli
    /// (yoksa state_root çatallanır).
    #[test]
    fn a_complete_relayed_proposal_replaces_a_partial_local_copy() {
        let state = test_state();
        store_default_authority_set(state.as_ref());
        let proposal_id = [0x51; 32];

        // Yerel KISMI kopya: esik 2, elde yalnizca 1 imza.
        let mut account = AccountState::default();
        account.contract_code =
            bincode::serialize(&sample_proposal_signed_by(proposal_id, 1)).unwrap();
        state
            .set_account(&BridgeManager::proposal_state_key(&proposal_id), account)
            .unwrap();

        // Blokla gelen TAM surum: 2 imza.
        let complete = sample_proposal_signed_by(proposal_id, 2);
        BridgeManager::ingest_relayed_proposals(state.as_ref(), std::slice::from_ref(&complete))
            .unwrap();

        let after = BridgeManager::load_proposal_from_state(state.as_ref(), &proposal_id)
            .unwrap()
            .expect("oneri state'te olmali");
        assert_eq!(
            after.signatures.len(),
            2,
            "esigi dolduran surum kismi yerel kopyanin uzerine yazilmali"
        );
    }

    /// Eşiği doldurmayan öneri boş düğüme de yazılmamalı (öneri zehirlenmesi).
    #[test]
    fn an_unverified_relayed_proposal_is_never_written() {
        let state = test_state();
        store_default_authority_set(state.as_ref());
        let proposal_id = [0x52; 32];

        let yetersiz = sample_proposal_signed_by(proposal_id, 1);
        BridgeManager::ingest_relayed_proposals(state.as_ref(), std::slice::from_ref(&yetersiz))
            .unwrap();
        assert!(
            BridgeManager::load_proposal_from_state(state.as_ref(), &proposal_id)
                .unwrap()
                .is_none(),
            "esigi doldurmayan oneri state'e YAZILMAMALI"
        );

        let imzasiz = sample_bridge_proposal(proposal_id, false);
        BridgeManager::ingest_relayed_proposals(state.as_ref(), std::slice::from_ref(&imzasiz))
            .unwrap();
        assert!(
            BridgeManager::load_proposal_from_state(state.as_ref(), &proposal_id)
                .unwrap()
                .is_none(),
            "imzasiz oneri state'e YAZILMAMALI"
        );
    }

    /// Uretici tarafi kilit: esigi dolduran bir oneri saglayamayan dugum, o
    /// `BridgeMint` islemini bloga HIC koymamali.
    #[test]
    fn a_producer_without_a_usable_proposal_cannot_supply_the_mint() {
        let state = test_state();
        store_default_authority_set(state.as_ref());
        let proposal_id = [0x53; 32];
        let tx = sample_bridge_mint_tx(proposal_id);

        assert!(
            !BridgeManager::can_supply_proposal_for(state.as_ref(), &tx),
            "onerisi HIC olmayan uretici saglayamaz"
        );

        let mut account = AccountState::default();
        account.contract_code =
            bincode::serialize(&sample_proposal_signed_by(proposal_id, 1)).unwrap();
        state
            .set_account(&BridgeManager::proposal_state_key(&proposal_id), account)
            .unwrap();
        assert!(
            !BridgeManager::can_supply_proposal_for(state.as_ref(), &tx),
            "esigi doldurmayan kismi oneriyle de saglayamaz"
        );

        let mut account = AccountState::default();
        account.contract_code =
            bincode::serialize(&sample_proposal_signed_by(proposal_id, 2)).unwrap();
        state
            .set_account(&BridgeManager::proposal_state_key(&proposal_id), account)
            .unwrap();
        assert!(
            BridgeManager::can_supply_proposal_for(state.as_ref(), &tx),
            "esigi dolduran oneriyle saglayabilir"
        );

        let duz = Transaction {
            tx_id: [0x54; 32],
            tx_type: TxType::Transfer,
            sender: String::new(),
            receiver: String::new(),
            amount: 1,
            payload: Vec::new(),
            signature: Vec::new(),
            timestamp: 0,
            nonce: 0,
            gas_limit: 1,
            gas_price: 1,
            chain_id: zagros_types::CHAIN_ID,
        };
        assert!(
            BridgeManager::can_supply_proposal_for(state.as_ref(), &duz),
            "kopru disi islem her zaman gecmeli"
        );
    }

    fn sample_bridge_proposal(proposal_id: Hash, executed: bool) -> BridgeProposal {
        BridgeProposal {
            proposal_id,
            tx_type: BridgeTxType::Mint,
            amount: 42 * TOKEN_DECIMAL,
            recipient: "0x00000000000000000000000000000000000abc".to_string(),
            source_chain: "Ethereum".to_string(),
            source_tx_hash: "0xdeadbeef".to_string(),
            timestamp: 1000,
            signatures: Vec::new(),
            executed,
            nonce: 7,
            auto_swap: true,
            amount_out_min: 0,
            claim_vouchers: Vec::new(),
        }
    }

    fn sample_bridge_mint_tx(tx_id: Hash) -> Transaction {
        Transaction {
            tx_id,
            tx_type: TxType::BridgeMintAndSwap,
            sender: "0x00000000000000000000000000000000000001".to_string(),
            amount: 0,
            receiver: "0x00000000000000000000000000000000000abc".to_string(),
            payload: Vec::new(),
            signature: Vec::new(),
            timestamp: 0,
            nonce: 0,
            gas_limit: 0,
            gas_price: 0,
            chain_id: 0,
        }
    }

    /// Gönderen tarafta öneri hâlâ AKTİF (henüz yürütülmemiş), ör. gerçek
    /// zamanlı gossip'te blok üretimiyle aynı anda yakalanmış olabilir.
    #[test]
    fn collect_proposals_for_relay_finds_active_proposal() {
        let state = test_state();
        let proposal_id = [0x42; 32];
        let mut account = AccountState::default();
        account.contract_code =
            bincode::serialize(&sample_bridge_proposal(proposal_id, false)).unwrap();
        state
            .set_account(&BridgeManager::proposal_state_key(&proposal_id), account)
            .unwrap();

        let collected = BridgeManager::collect_proposals_for_relay(
            state.as_ref(),
            &[sample_bridge_mint_tx(proposal_id)],
        );
        assert_eq!(collected.len(), 1);
        assert_eq!(collected[0].proposal_id, proposal_id);
        assert!(!collected[0].executed);
    }

    /// Gönderen tarafta öneri zaten arşivde: tarihsel senkronda normal durum.
    #[test]
    fn collect_proposals_for_relay_falls_back_to_archived_proposal() {
        let state = test_state();
        let proposal_id = [0x43; 32];
        let mut account = AccountState::default();
        account.contract_code =
            bincode::serialize(&sample_bridge_proposal(proposal_id, false)).unwrap();
        state
            .set_account(&BridgeManager::proposal_state_key(&proposal_id), account)
            .unwrap();
        BridgeManager::mark_executed_in_state(state.as_ref(), &proposal_id).unwrap();

        // Aktif anahtar artık boşaltılmış olmalı (mark_executed_in_state'in davranışı).
        assert!(
            BridgeManager::load_proposal_from_state(state.as_ref(), &proposal_id)
                .unwrap()
                .is_none()
        );

        let collected = BridgeManager::collect_proposals_for_relay(
            state.as_ref(),
            &[sample_bridge_mint_tx(proposal_id)],
        );
        assert_eq!(collected.len(), 1, "arşivlenmiş öneri de bulunmalı");
        assert_eq!(collected[0].proposal_id, proposal_id);
    }

    /// `collect_proposals_for_relay`, köprüyle ilgisi olmayan (`Transfer`)
    /// işlemleri için hiçbir şey döndürmemeli, tüm blok gövdesini gereksiz
    /// yere taramamalı/hataya yol açmamalı.
    #[test]
    fn collect_proposals_for_relay_ignores_non_bridge_transactions() {
        let state = test_state();
        let mut plain_transfer = sample_bridge_mint_tx([0x44; 32]);
        plain_transfer.tx_type = TxType::Transfer;
        let collected =
            BridgeManager::collect_proposals_for_relay(state.as_ref(), &[plain_transfer]);
        assert!(collected.is_empty());
    }

    /// 🎯 Gönderen tarafta ARŞİVLENMİŞ öneri, alıcıda `ingest_relayed_proposals`
    /// sonrası AKTİF olmalı; alıcının kendi yürütmesi onu arşive taşır.
    #[test]
    fn ingest_relayed_proposals_resets_executed_flag_so_receiver_can_replay_it() {
        let sender_state = test_state();
        let proposal_id = [0x45; 32];
        // 🚨 Oneri artik GECERLI M-of-N imzasiyla kurulur,
        // `ingest_relayed_proposals` dogrulanmamis bayti ARTIK HIC yazmiyor.
        store_default_authority_set(sender_state.as_ref());
        let mut account = AccountState::default();
        account.contract_code = bincode::serialize(&signed_sample_proposal(proposal_id)).unwrap();
        sender_state
            .set_account(&BridgeManager::proposal_state_key(&proposal_id), account)
            .unwrap();
        BridgeManager::mark_executed_in_state(sender_state.as_ref(), &proposal_id).unwrap();
        let relayed = BridgeManager::collect_proposals_for_relay(
            sender_state.as_ref(),
            &[sample_bridge_mint_tx(proposal_id)],
        );
        assert_eq!(relayed.len(), 1);
        assert!(
            relayed[0].executed,
            "gönderenin kendi kopyası yürütülmüş olmalı"
        );

        // Alıcı (follower), bu öneriyi HİÇ görmemiş, tertemiz bir state.
        let receiver_state = test_state();
        store_default_authority_set(receiver_state.as_ref());
        BridgeManager::ingest_relayed_proposals(receiver_state.as_ref(), &relayed).unwrap();

        let hydrated =
            BridgeManager::load_proposal_from_state(receiver_state.as_ref(), &proposal_id)
                .unwrap()
                .expect("ingest sonrası aktif anahtarda bulunmalı");
        assert!(
            !hydrated.executed,
            "alıcı için taze/bekleyen sayılmalı - aksi halde proposal_is_executable onu reddeder"
        );
        assert_eq!(hydrated.amount, relayed[0].amount);
        assert_eq!(hydrated.recipient, relayed[0].recipient);

        // Henüz alıcının KENDİ yürütmesi olmadığından arşivde olmamalı.
        assert!(BridgeManager::load_archived_proposal_from_state(
            receiver_state.as_ref(),
            &proposal_id
        )
        .unwrap()
        .is_none());

        // Ve gerçekten yürütülebilir durumda: proposal_is_executable eşiği/
        // zaman kilidini geçer (imza yok ama required_signatures=0 ile test
        // edilir, burada sadece `executed` bayrağının davranışı hedefleniyor).
        assert!(BridgeManager::proposal_is_executable(
            &hydrated,
            0,
            0,
            current_time_ms()
        ));
    }
}
