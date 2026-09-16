// Zagros Network, Core Type Definitions
// Ortak tip tanımlamaları ve primitives

pub mod bridge_amount;
pub mod config;
/// Konsensüs tipleri (CONSENSUS-SPEC v0.2): header v2, vote, QC, evidence,
/// validator set, domain-separated imza yükü, ChainParams.
pub mod consensus;
pub mod eip712;
pub mod gas;

pub use gas::{
    base_gas_fee_from_reserves, ddos_stress_multiplier, evm_intrinsic_gas,
    gas_multiplier_for_tx_type, GasCalculator,
};

pub use alloy_primitives::U256;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

// BLOCKCHAIN PRIMITIVES

pub type Hash = [u8; 32];
pub type Address = String; // Zagros address format: "zcx..."
pub type Signature = Vec<u8>;
pub type BlockNumber = u64;
pub type Nonce = u64;
pub type Balance = u128;

/// Slashing proof. 🚨 ÇOKLU VALİDATOR ENGELLEYİCİ: yalnız imzaların adrese
/// çözüldüğü doğrulanır, hash'lerin gerçek bloklara ait olduğu değil; blok
/// geçmişine çapraz doğrulama olmadan çok düğümlü ağda KULLANILAMAZ.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingProof {
    pub validator: Address,
    pub block_hash: Hash,
    pub conflicting_block_hash: Hash,
    pub first_signature: Signature,
    pub second_signature: Signature,
    pub epoch: u64,
    pub timestamp: u64,
}

impl SlashingProof {
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data)
            .map_err(|e| ZagrosError::Other(format!("Failed to deserialize slashing proof: {}", e)))
    }

    pub fn validate(&self) -> Result<()> {
        // Validator address must be valid
        if !Transaction::validate_address(&self.validator) {
            return Err(ZagrosError::Other(
                "Invalid validator address in slashing proof".to_string(),
            ));
        }

        if self.first_signature.len() != 65 || self.second_signature.len() != 65 {
            return Err(ZagrosError::Other(
                "Invalid slashing proof signature length".to_string(),
            ));
        }

        if self.block_hash == self.conflicting_block_hash {
            return Err(ZagrosError::Other(
                "Conflicting blocks must differ".to_string(),
            ));
        }

        if self.timestamp == 0 {
            return Err(ZagrosError::Other(
                "Slashing proof timestamp cannot be zero".to_string(),
            ));
        }

        let current_time = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        {
            Ok(duration) => duration.as_secs(),
            Err(err) => {
                return Err(ZagrosError::Other(format!(
                    "System time error while validating slashing proof: {}",
                    err
                )));
            }
        };

        if self.timestamp > current_time + 300 {
            return Err(ZagrosError::Other(
                "Slashing proof timestamp too far in the future".to_string(),
            ));
        }
        if self.timestamp < current_time.saturating_sub(86400 * 30) {
            return Err(ZagrosError::Other("Slashing proof is too old".to_string()));
        }

        Ok(())
    }

    /// Kriptografik equivocation kanıtı: iki imza da iki FARKLI blok hash'i
    /// üzerinde suçlanan validator adresine çözülmeli. `validate()` yalnız şekli
    /// denetler, asıl kanıt kontrolü budur.
    pub fn verify_double_sign(&self) -> bool {
        let first_signer = recover_signer_address(&self.block_hash, &self.first_signature);
        let second_signer =
            recover_signer_address(&self.conflicting_block_hash, &self.second_signature);
        match (first_signer, second_signer) {
            (Some(first), Some(second)) => {
                first.eq_ignore_ascii_case(&self.validator)
                    && second.eq_ignore_ascii_case(&self.validator)
            }
            _ => false,
        }
    }
}

/// Slash sebebi. Yalnız `DoubleSign` gerçek kanıta bağlı; diğerleri "gelecek"
/// işaretli, hiçbir yol üretmez (doğrulama olmadan açmak sahte slashing'e kapı açar).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlashReason {
    /// Aynı yükseklikte iki farklı bloğu imzalamak, TEK canlı, kanıtlanabilir
    /// sebep (bkz. `SlashingProof`).
    DoubleSign,
    /// GELECEK: köprü mint/unlock önerisine sahte/geçersiz imza. Henüz
    /// hiçbir kod yolu bunu üretmiyor, `BridgeManager` imza doğrulaması
    /// zaten fail-closed olduğundan sahte imza asla proposal'a giremiyor.
    ForgedBridgeSignature,
    /// GELECEK: geçersiz/kurallara aykırı governance önerisi sunmak. Henüz
    /// hiçbir kod yolu bunu üretmiyor.
    InvalidProposal,
    /// GELECEK: çelişkili/çifte oy. `Vote`'un kendisi zaten `proposal.voters`
    /// seti ile çifte oyu reddediyor, bu sebep şimdilik erişilemez.
    ConflictingVote,
    /// GELECEK: geçersiz blok üretimi (çoklu-validator/P2P konsensüsü
    /// gerektirir, bkz. proje hafızası, tek-node'da anlamsız).
    InvalidBlockProduction,
    /// CANLI, `SlashValidator` admin yolu: kanıta değil zaman sınırlı admin
    /// takdirine dayanır; `DoubleSign` ile karıştırılmamalı.
    AdminEmergencySeizure,
}

/// Slash olayının kalıcı denetim kaydı (`__SLASH_HISTORY__`, sınırlı boyut,
/// en eski atılır); her başarılı `SlashValidator`/`ReportMalicious`ta eklenir.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashRecord {
    pub index: u64,
    pub target: Address,
    pub reason: SlashReason,
    pub confiscated_amount: u128,
    pub timestamp: u128,
}

/// En son `Executor::distribute_staking_reward` çağrısının anlık görüntüsü,
/// canlı `acc`/`reward_debt` muhasebesinden BAĞIMSIZ, salt gözlemlenebilirlik/
/// denetim amaçlı (bkz. `Executor::record_reward_snapshot`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardSnapshot {
    pub total_staked: u128,
    pub accumulated_reward_per_share: u128,
    pub staker_share: u128,
    pub validator_share: u128,
    pub timestamp: u128,
}

/// G7 (§11): `ReportMalicious` yükü. Eski `SlashingProof` yolu korunur;
/// `ConsensusEvidence` BFT Ed25519 kanıtını taşır, geçmiş epoch kümesine karşı doğrulanır.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EquivocationReport {
    Legacy(SlashingProof),
    ConsensusEvidence(crate::consensus::Evidence),
}

impl EquivocationReport {
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| {
            ZagrosError::Other(format!("Failed to deserialize equivocation report: {}", e))
        })
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("EquivocationReport serilestirilebilir")
    }
}

pub fn recover_signer_address(message_hash: &[u8; 32], signature: &[u8]) -> Option<Address> {
    use secp256k1::{ecdsa::RecoverableSignature, ecdsa::RecoveryId, Message, Secp256k1};
    use sha3::{Digest, Keccak256};

    if signature.len() != 65 {
        return None;
    }

    let message = Message::from_digest_slice(message_hash).ok()?;

    let recovery_byte = signature[64];
    let recovery_id = match recovery_byte {
        0 | 1 => recovery_byte,
        27 | 28 => recovery_byte - 27,
        v if v >= 35 => (v - 35) % 2,
        _ => return None,
    };
    let recovery_id = RecoveryId::from_i32(recovery_id as i32).ok()?;

    let signature_bytes: [u8; 64] = signature[0..64].try_into().ok()?;

    // 🛡️ Strict low-S: (r, n−s) ikizi aynı adrese çözülür ama farklı tx_id
    // üretip dedup/izlemeyi bozardı; high-S reddedilir.
    let standard_sig = secp256k1::ecdsa::Signature::from_compact(&signature_bytes).ok()?;
    let mut normalized = standard_sig;
    normalized.normalize_s();
    if normalized.serialize_compact() != standard_sig.serialize_compact() {
        return None;
    }

    let recoverable_sig = RecoverableSignature::from_compact(&signature_bytes, recovery_id).ok()?;

    let secp = Secp256k1::new();
    let public_key = secp.recover_ecdsa(&message, &recoverable_sig).ok()?;

    let pub_key_bytes = public_key.serialize_uncompressed();
    let mut hasher = Keccak256::new();
    hasher.update(&pub_key_bytes[1..]);
    let hash = hasher.finalize();
    Some(format!("0x{}", hex::encode(&hash[12..])))
}

// NETWORK CONSTANTS (ANAYASA, TOKENOMICS CONSTITUTION)

pub const CHAIN_ID: u64 = 21072026; // Zagros Network Mainnet Chain ID

/// EVM çağrısının native `TxType`ı ve tutarın calldata'dan okunup okunmayacağı.
/// 🚨 TEK KAYNAK: kurulum ve doğrulama bunu kullanır, ayrı yazılsa ayrışırdı.
pub fn native_tx_type_for_evm_call(receiver: &str, data: &[u8]) -> Option<(TxType, Option<u128>)> {
    // calldata'nın ilk argümanı (`data[4..36]`, 32 baytlık big-endian), 128
    // biti aşarsa `None` (u128'e sığmaz).
    let amount_from_data = |data: &[u8]| -> Option<u128> {
        if data.len() < 36 {
            return None;
        }
        if data[4..20].iter().any(|b| *b != 0) {
            return None;
        }
        let mut low = [0u8; 16];
        low.copy_from_slice(&data[20..36]);
        Some(u128::from_be_bytes(low))
    };

    if data.len() >= 4 && data[0..4] == [0x34, 0xc5, 0x16, 0x3e] {
        Some((TxType::SwapBuy, amount_from_data(data)))
    } else if data.len() >= 4 && data[0..4] == [0xfa, 0x88, 0xf0, 0x5c] {
        Some((TxType::SwapSell, amount_from_data(data)))
    } else if data.len() >= 4 && data[0..4] == [0x2e, 0x17, 0xde, 0x78] {
        Some((TxType::UnstakeZagros, amount_from_data(data)))
    } else if data.len() >= 4 && data[0..4] == [0x42, 0x96, 0x6c, 0x68] {
        Some((TxType::BridgeBurn, amount_from_data(data)))
    } else if data.len() >= 4
        && (data[0..4] == [0x06, 0x69, 0x6e, 0xc0] || data[0..4] == [0xa0, 0x3b, 0x61, 0x62])
    {
        Some((TxType::BridgeSwapAndBurn, amount_from_data(data)))
    } else if data.len() == 4 && data[0..4] == [58, 75, 102, 241] {
        Some((TxType::StakeZagros, None))
    } else if data.len() == 4
        && data[0..4] == [0x37, 0x25, 0x00, 0xab]
        && receiver == "0x0000000000000000000000000000000000000003"
    {
        Some((TxType::ClaimReward, None))
    } else if data.len() >= 4
        && data[0..4] == [0xbc, 0xc6, 0x58, 0x7f]
        && receiver == "0x0000000000000000000000000000000000000006"
    {
        Some((TxType::RegisterValidator, None))
    } else if data.len() >= 4
        && data[0..4] == [0x4a, 0x7c, 0x33, 0x2f]
        && receiver == "0x0000000000000000000000000000000000000006"
    {
        Some((TxType::RotateConsensusKey, None))
    } else if data.len() >= 4
        && data[0..4] == [0xd3, 0xf6, 0x3e, 0xf9]
        && receiver == "0x0000000000000000000000000000000000000008"
    {
        // ApproveValidator: admin multisig (Faz A, 3/5) bir Candidate'i onaylar.
        // Sentinel 0x…08 = VALIDATOR_ADMIN_ADDRESS. Payload = AdminActionPayload
        // bincode'u (seçici SONRASI); admin imzaları payload içinde taşınır.
        Some((TxType::ApproveValidator, None))
    } else if data.len() >= 4
        && data[0..4] == [0xb2, 0xf5, 0x69, 0xc5]
        && receiver == "0x0000000000000000000000000000000000000008"
    {
        // RemoveValidator: admin multisig bir adayı/validatörü kümeden çıkarır.
        Some((TxType::RemoveValidator, None))
    } else if data.len() > 4 && data[0..4] == [0x62, 0x16, 0xe6, 0xf0] {
        // 🚨 `reportEquivocation(bytes)`: çift imza kanıtını zincire taşıyan TEK yol.
        // Alıcı suçlanan validatörün adresi (sabit sentinel şart değil, ayırt edici
        // seçici); kanıt payload'ı seçiciden sonra gelir (`EquivocationReport` bincode).
        Some((TxType::ReportMalicious, None))
    } else if data.len() > 4
        && data[0..4] == [0xd2, 0x38, 0x31, 0x36]
        && receiver == GOVERNANCE_ADDRESS
    {
        // 🗳️ `submitProposal(bytes)`: payload seçici sonrası ham bincode
        // (`reportEquivocation` deseni); executor tipli/metin ayrımını yapar.
        Some((TxType::SubmitProposal, None))
    } else if data.len() > 4
        && data[0..4] == [0xe9, 0xdc, 0x06, 0x14]
        && receiver == GOVERNANCE_ADDRESS
    {
        // 🗳️ `vote(bytes)`: payload TAM 33 bayt (32 id + 1 tercih); ABI
        // `vote(bytes32,bool)` 64 bayt üretip reddedilirdi.
        Some((TxType::Vote, None))
    } else if receiver == SLASH_VALIDATOR_ADDRESS {
        Some((TxType::SlashValidator, None))
    } else {
        None
    }
}

/// Bir EVM işleminin (alıcı, calldata, value) üçlüsünden native
/// `(tx_type, amount, payload)` türetir. `decode_and_convert_tx`'in
/// türetme sırasıyla BİREBİR aynıdır (bkz. `native_tx_type_for_evm_call`).
pub fn derive_native_call(
    receiver: &str,
    data: &[u8],
    value: u128,
    to_is_none: bool,
) -> (TxType, u128, Vec<u8>) {
    let mut amount = value;
    let tx_type =
        if let Some((native_type, maybe_amount)) = native_tx_type_for_evm_call(receiver, data) {
            if let Some(a) = maybe_amount {
                amount = a;
            }
            native_type
        } else if to_is_none {
            TxType::ContractCall {
                data: data.to_vec(),
            }
        } else if data.is_empty() {
            TxType::Transfer
        } else {
            TxType::ContractCall {
                data: data.to_vec(),
            }
        };
    // RegisterValidator/RotateConsensusKey/SubmitProposal/Vote payload'ı seçici
    // sonrası ham baytlar (Vote için TAM 33 bayt).
    let payload = if matches!(
        tx_type,
        TxType::RegisterValidator
            | TxType::RotateConsensusKey
            | TxType::ReportMalicious
            | TxType::ApproveValidator
            | TxType::RemoveValidator
            | TxType::SubmitProposal
            | TxType::Vote
    ) {
        data.get(4..).map(|rest| rest.to_vec()).unwrap_or_default()
    } else {
        data.to_vec()
    };
    (tx_type, amount, payload)
}

/// Keyless deterministik dağıtım deployer adresleri; EIP-155 kuralının TEK
/// istisnası. Özel anahtarı kimsede yok; eklenecek adres aynı ölçütü karşılamalı.
pub const KEYLESS_DEPLOYERS: [&str; 1] = [
    // Multicall3 deployer'ı (kanonik kontrat: 0xcA11bde05977b3631167028862bE2a173976CA11,
    // önceden imzalı işlem: github.com/mds1/multicall3 README).
    "0x05f32b3cc3888453ff71b01135b34ff8e41263f2",
];

/// Adres (0x'li, büyük/küçük harf duyarsız) bilinen keyless deployer'lardan mı?
pub fn is_keyless_deployer(address: &str) -> bool {
    let normalized = address.to_lowercase();
    KEYLESS_DEPLOYERS.iter().any(|d| *d == normalized)
}

/// Keyless deployment'ın KANONİK kontrat adresleri (`deployer + nonce=0`
/// CREATE). Nonce'ları replay_guard ile taşınırsa CREATE `CreateCollision`
/// verir ve adres bir daha üretilemez (Multicall3 0xcA11.. böyle kaybedilmişti).
pub const KEYLESS_CONTRACT_ADDRESSES: [&str; 1] = [
    // Multicall3 kanonik kontratı (deployer 0x05f32b3c...'nin nonce=0 CREATE'i).
    "0xca11bde05977b3631167028862be2a173976ca11",
];

/// replay_guard NONCE taşımasından muaf adres mi? Hem keyless deployer'lar hem
/// onların ürettiği kanonik kontratlar muaftır, ikisi de deterministik olarak
/// yeniden kurulur, taşınan bir nonce yeniden-kurulumu bozar.
pub fn is_replay_guard_nonce_exempt(address: &str) -> bool {
    let normalized = address.to_lowercase();
    is_keyless_deployer(&normalized) || KEYLESS_CONTRACT_ADDRESSES.iter().any(|c| *c == normalized)
}

/// Executor state_root davranışının sürümü (konsensüs kritik); kökü etkileyen
/// her değişiklik artırmalı (v2 slot remove, v3 ayrı transfer anahtarları, v4
/// CANCUN). Artış tüm node'ların eşzamanlı yükseltilmesini gerektirir.
pub const EXECUTOR_STATE_TRANSITION_VERSION: u32 = 4;

/// `EXECUTOR_STATE_TRANSITION_VERSION`'ın diskte saklandığı sabit anahtar.
pub const EXECUTOR_STATE_VERSION_KEY: &str = "__EXECUTOR_STATE_VERSION__";

/// 🛡️ Açılış kontrolünün SAF karar mantığı (I/O yok): node'un başlayıp
/// başlamayacağını ve nedenini belirler. Fail-closed: operatörün AÇIKÇA
/// onaylamadığı konsensüs kırıcı sürümle SESSİZCE başlamayı önler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutorVersionDecision {
    /// Bu çalıştırmada yeni oluşturulan taze bir genesis, onaya gerek yok.
    FreshGenesis,
    /// Diskteki sürüm zaten ikilininkiyle eşleşiyor, hiçbir şey yapılmaz.
    UpToDate,
    /// İleri yükseltme gerekiyor VE operatör `acknowledged_executor_state_version`
    /// alanına TAM OLARAK bu ikilinin sürümünü yazarak onaylamış, devam
    /// edilir, diskteki sürüm güncellenir.
    UpgradeAcknowledged { from: u32 },
    /// İleri yükseltme gerekiyor AMA operatör onaylamamış, node BAŞLAMAMALI
    /// (fail-closed).
    UpgradeNotAcknowledged { from: u32 },
    /// Geri sarma: diskteki sürüm bu ikiliden YENİ. Node ASLA başlamamalı,
    /// hiçbir onay bunu geçersiz kılamaz, tek çözüm en az diskteki sürümü
    /// çalıştıran bir ikiliye yükseltmektir.
    Downgrade { disk_version: u32 },
}

/// `stored_version` diskteki değer (`None` = hiç yazılmamış), `should_initialize_genesis`
/// = `block_0` yoktu (taze genesis), `acknowledged_version` config'ten.
pub fn decide_executor_version_action(
    stored_version: Option<u32>,
    should_initialize_genesis: bool,
    current_version: u32,
    acknowledged_version: Option<u32>,
) -> ExecutorVersionDecision {
    match stored_version {
        None if should_initialize_genesis => ExecutorVersionDecision::FreshGenesis,
        None => {
            // 🚨 Var olan DB'de sürüm anahtarı yoksa state kesinlikle
            // `current_version - 1` (izleme öncesi son sürüm) ile üretilmiştir.
            let implicit_version = current_version.saturating_sub(1);
            if acknowledged_version == Some(current_version) {
                ExecutorVersionDecision::UpgradeAcknowledged {
                    from: implicit_version,
                }
            } else {
                ExecutorVersionDecision::UpgradeNotAcknowledged {
                    from: implicit_version,
                }
            }
        }
        Some(v) if v < current_version => {
            if acknowledged_version == Some(current_version) {
                ExecutorVersionDecision::UpgradeAcknowledged { from: v }
            } else {
                ExecutorVersionDecision::UpgradeNotAcknowledged { from: v }
            }
        }
        Some(v) if v > current_version => ExecutorVersionDecision::Downgrade { disk_version: v },
        Some(_) => ExecutorVersionDecision::UpToDate,
    }
}

#[cfg(test)]
mod executor_version_decision_tests {
    use super::*;

    #[test]
    fn fresh_genesis_needs_no_acknowledgement() {
        assert_eq!(
            decide_executor_version_action(None, true, 2, None),
            ExecutorVersionDecision::FreshGenesis
        );
        // Genesis sırasında yanlışlıkla dolu bir `acknowledged_version` olsa
        // bile sonucu DEĞİŞTİRMEMELİ, taze genesis her zaman taze genesistir.
        assert_eq!(
            decide_executor_version_action(None, true, 2, Some(2)),
            ExecutorVersionDecision::FreshGenesis
        );
    }

    #[test]
    fn preexisting_database_without_version_key_is_treated_as_pre_tracking_upgrade() {
        assert_eq!(
            decide_executor_version_action(None, false, 2, None),
            ExecutorVersionDecision::UpgradeNotAcknowledged { from: 1 }
        );
        assert_eq!(
            decide_executor_version_action(None, false, 2, Some(2)),
            ExecutorVersionDecision::UpgradeAcknowledged { from: 1 }
        );
    }

    #[test]
    fn forward_upgrade_without_acknowledgement_is_blocked() {
        assert_eq!(
            decide_executor_version_action(Some(1), false, 2, None),
            ExecutorVersionDecision::UpgradeNotAcknowledged { from: 1 }
        );
    }

    #[test]
    fn forward_upgrade_with_wrong_acknowledged_version_is_still_blocked() {
        // Operatör ESKİ bir sürümü onaylamış (ör. config.toml güncellenmemiş),
        // bu, YANLIŞLIKLA geçerli sayılmamalı.
        assert_eq!(
            decide_executor_version_action(Some(1), false, 3, Some(2)),
            ExecutorVersionDecision::UpgradeNotAcknowledged { from: 1 }
        );
    }

    #[test]
    fn forward_upgrade_with_exact_acknowledgement_proceeds() {
        assert_eq!(
            decide_executor_version_action(Some(1), false, 2, Some(2)),
            ExecutorVersionDecision::UpgradeAcknowledged { from: 1 }
        );
    }

    #[test]
    fn matching_version_is_a_pure_noop() {
        assert_eq!(
            decide_executor_version_action(Some(2), false, 2, None),
            ExecutorVersionDecision::UpToDate
        );
        // Kalan (artık geçersiz) bir onay değeri de sonucu değiştirmemeli.
        assert_eq!(
            decide_executor_version_action(Some(2), false, 2, Some(2)),
            ExecutorVersionDecision::UpToDate
        );
    }

    #[test]
    fn downgrade_is_never_acknowledgeable() {
        assert_eq!(
            decide_executor_version_action(Some(3), false, 2, None),
            ExecutorVersionDecision::Downgrade { disk_version: 3 }
        );
        // Operatör YANLIŞLIKLA/kasıtlı olarak bir onay yazmış olsa bile geri
        // sarma ASLA geçirilmemeli, onaylanacak bir "ileri" hareket yok.
        assert_eq!(
            decide_executor_version_action(Some(3), false, 2, Some(2)),
            ExecutorVersionDecision::Downgrade { disk_version: 3 }
        );
    }
}

// TOKEN DECIMALS
// Zagros uses 18 decimals internally for standard EVM compatibility.
pub const TOKEN_DECIMAL: u128 = 1_000_000_000_000_000_000; // 10^18 = 1 token (18 decimals)

fn group_thousands(value: u128) -> String {
    let digits = value.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, digit) in digits.chars().rev().enumerate() {
        if i != 0 && i % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped.chars().rev().collect()
}

/// Ham 18 ondalık tutarı binlik ayraçlı, iki ondalıklı dizgeye çevirir
/// (132976887380675512532544 -> "132,976.88"). Yuvarlamaz, keser: bakiye
/// ekranda gerçekte olandan fazla görünmesin.
pub fn format_token_amount(raw: u128) -> String {
    let whole = raw / TOKEN_DECIMAL;
    let fractional = ((raw % TOKEN_DECIMAL) * 100) / TOKEN_DECIMAL;
    format!("{}.{:02}", group_thousands(whole), fractional)
}

/// Sabit protokol sabitleri (Total Supply, Genesis AMM hedefi vb.) için,
/// bunlar tasarım gereği asla kesirli olamaz, ondalık eklemek yapay bir
/// hassasiyet izlenimi verir.
pub fn format_token_amount_whole(raw: u128) -> String {
    group_thousands(raw / TOKEN_DECIMAL)
}

#[cfg(test)]
mod format_tests {
    use super::*;

    #[test]
    fn format_token_amount_groups_thousands_and_truncates_to_two_decimals() {
        // 132976.887380675512532544 ZAGROS baz birimde
        let raw = 132_976_887_380_675_512_532_544u128;
        assert_eq!(format_token_amount(raw), "132,976.88");
    }

    #[test]
    fn format_token_amount_truncates_rather_than_rounds() {
        // 1.999999... -> "1.99", 2.00'a yuvarlanmamalı
        let raw = TOKEN_DECIMAL + TOKEN_DECIMAL - 1;
        assert_eq!(format_token_amount(raw), "1.99");
    }

    #[test]
    fn format_token_amount_handles_zero_and_sub_cent_dust() {
        assert_eq!(format_token_amount(0), "0.00");
        assert_eq!(format_token_amount(1), "0.00"); // 1 baz birim, kuruşun çok altında
    }

    #[test]
    fn format_token_amount_whole_groups_thousands_without_decimals() {
        assert_eq!(
            format_token_amount_whole(42_000_000 * TOKEN_DECIMAL),
            "42,000,000"
        );
        assert_eq!(
            format_token_amount_whole(41_999_999 * TOKEN_DECIMAL),
            "41,999,999"
        );
    }
}

// VALIDATOR BARAJI: sabit `MIN_VALIDATOR_STAKE` yok; teminat zincir üstü
// `ChainParams::min_validator_stake_zerenya`, havuz oranıyla ZAGROS'a çevrilir.

/// Protokol gelirinin staker'lar (`acc`-share) ile aktif validator(ler) arası
/// bölüşümü, baz puan. Toplam HER ZAMAN 10000 (test:
/// `staker_and_validator_reward_bps_sum_to_100_percent`); başka yerde magic number yazılmaz.
pub const STAKER_REWARD_BPS: u128 = 8000; // %80
pub const VALIDATOR_REWARD_BPS: u128 = 2000; // %20

/// Slash edilen validator bu süre boyunca yeniden `RegisterValidator`
/// gönderemez (`AccountState.jailed_until`); taze sermayeyle anında dönmesin.
/// 7 gün: `UnstakeZagros`'un 48 saatlik kilidinden kasıtlı olarak uzun.
pub const JAIL_DURATION_SECONDS: u128 = 7 * 24 * 60 * 60; // 604,800 sn

/// 🚨 D14 kural paketinin aktivasyon yüksekliği (kendine transfer reddi, ücret
/// kelepçesi, kilit kanonikleştirme vb.); `blok < D14` eski kurallarla oynatılır. DEĞİŞTİRİLEMEZ.
pub const D14_RULES_ACTIVATION_HEIGHT: u64 = 9400;

/// 🗳️ İadeli depozito kapısı: bu yükseklikten itibaren bedel kasada tutulur,
/// yeter sayıda iade, yoksa Hevsel'e; kapı öncesi öneriler eski kuralla oynatılır.
pub const GOV_DEPOSIT_ACTIVATION_HEIGHT: u64 = 10_300;

/// Anti-flash-stake hakediş süresi: `StakeZagros` ile eklenen miktar bu süre
/// geçmeden ödül muhasebesine katılmaz (`pending_stake_*`, `settle_pending_stake`).
/// 1 saat: tek ücret olayını atlatmaya yeter, uzun vadeli staker'ı cezalandırmaz.
pub const REWARD_VESTING_SECONDS: u128 = 60 * 60; // 3,600 sn

#[cfg(test)]
mod validator_reward_split_tests {
    use super::*;

    #[test]
    fn staker_and_validator_reward_bps_sum_to_100_percent() {
        assert_eq!(STAKER_REWARD_BPS + VALIDATOR_REWARD_BPS, 10_000);
    }

    /// 🚨 Regresyon: dApp'in `slash(address)` çağrısının TAM biçimi (seçici
    /// `0xc96be4cb` + sağa hizalı 32 bayt adres) `from_utf8` ile okunursa boş
    /// adrese düşer; bu test o yolu kilitler.
    #[test]
    fn slash_target_address_decodes_the_real_abi_encoded_call_from_command_view() {
        let real_target = "0x1234567890123456789012345678901234567890";
        let mut payload = vec![0xc9, 0x6b, 0xe4, 0xcb]; // keccak256("slash(address)")[0..4]
        payload.extend_from_slice(&[0u8; 12]); // sol dolgu (padding)
        payload.extend_from_slice(&hex::decode(&real_target[2..]).unwrap());
        assert_eq!(payload.len(), 36);
        assert_eq!(
            slash_target_address(SLASH_VALIDATOR_ADDRESS, &payload),
            real_target
        );
    }

    #[test]
    fn slash_target_address_decodes_a_selector_less_padded_word() {
        let real_target = "0x1234567890123456789012345678901234567890";
        let mut payload = vec![0u8; 12];
        payload.extend_from_slice(&hex::decode(&real_target[2..]).unwrap());
        assert_eq!(payload.len(), 32);
        assert_eq!(
            slash_target_address(SLASH_VALIDATOR_ADDRESS, &payload),
            real_target
        );
    }

    #[test]
    fn slash_target_address_decodes_a_raw_20_byte_address() {
        let real_target = "0x1234567890123456789012345678901234567890";
        let payload = hex::decode(&real_target[2..]).unwrap();
        assert_eq!(payload.len(), 20);
        assert_eq!(
            slash_target_address(SLASH_VALIDATOR_ADDRESS, &payload),
            real_target
        );
    }

    /// Geriye dönük uyumluluk: eski (gerçekte hiç kullanılmamış) ham-UTF-8
    /// biçimi de hâlâ çalışmalı.
    #[test]
    fn slash_target_address_resolves_sentinel_receiver_from_legacy_utf8_payload() {
        let real_target = "0x1234567890123456789012345678901234567890";
        assert_eq!(
            slash_target_address(SLASH_VALIDATOR_ADDRESS, real_target.as_bytes()),
            real_target
        );
    }

    #[test]
    fn slash_target_address_passes_through_a_direct_receiver() {
        let direct = "0x1234567890123456789012345678901234567890";
        assert_eq!(slash_target_address(direct, b"ignored"), direct);
    }
}

// MAKSİMUM ARZ, DEĞİŞMEZ ANAYASA KURALI: 42 milyon ZAGROS, genesis sonrası
// mint/issue/create yolu YOK.
pub const MAX_SUPPLY: u128 = 42_000_000 * TOKEN_DECIMAL; // 42M ZAGROS tokens (internal format)
pub const TOTAL_SUPPLY: u128 = MAX_SUPPLY; // Alias for compatibility

// GENESIS DAĞILIMI: tüm arz otonom likidite havuzunda, kurucu 0 likit ZAGROS
// (C-3 merkeziyetsizlik savunması: sabit çarpım eğrisi + %5/60 sn devre
// kesici altında büyük çekim üstel maliyetli). MAINNET: FOUNDER_GENESIS_ZAGROS = 0.
pub const GENESIS_POOL_ZAGROS: u128 = MAX_SUPPLY - FOUNDER_GENESIS_ZAGROS; // = MAX_SUPPLY (kurucu payı 0)

/// ZERENYA genesis'te 11.000 birim (10.500 havuz + 500 kurucu). Arz SABİT
/// DEĞİL: genesis sonrası tek değişim yolu köprü (1 PAXG kilit = 1 ZERENYA).
pub const GENESIS_POOL_ZERENYA: u128 = 10_500 * TOKEN_DECIMAL; // 10.500 ZERENYA, 1:1 gerçek PAXG ile teminatlı

/// Genesis ANINDAKİ toplam ZERENYA arzı (havuz + kurucu). Yalnızca genesis
/// invariant kontrolü için var, `MAX_SUPPLY`'ın aksine ZERENYA'nın kalıcı
/// arz tavanı DEĞİLDİR, genesis sonrası köprü mint/burn ile serbestçe değişir.
pub const GENESIS_TOTAL_ZERENYA: u128 = GENESIS_POOL_ZERENYA + FOUNDER_GENESIS_ZERENYA;

pub const LIQUIDITY_POOL_ADDRESS: &str = "0x0000000000000000000000000000000000000000"; // Autonomous DEX Pool (System Controlled)

/// ZERENYA ERC-20 sözleşme adresi: native bakiye üzerinde çalışan precompile
/// emülasyonu (`evm.rs`), gerçek wrapper değil.
pub const ZERENYA_TOKEN_ADDRESS: &str = "0x0000000000000000000000000000000000000002";

/// Validator / Staking ödül havuzu: Ağda harcanan tüm Gas ücretlerinin toplandığı hazine adresi.
/// Ayrıca Claim Reward router adresi olarak da kullanılır.
pub const VALIDATOR_REWARD_POOL: &str = "0x0000000000000000000000000000000000000003";

/// İnfaz komutlarını tetikleyen özel sistem adresi.
pub const SLASH_VALIDATOR_ADDRESS: &str = "0x0000000000000000000000000000000000000007";

/// Governance (öneri sunma + oylama) sentinel adresi; `native_tx_type_for_evm_call`
/// tablosundaki girişi olmadan hiçbir öneri gönderilemez (tüm işlemler
/// `eth_sendRawTransaction` + bu tablodan geçer). Adres canlı zincirde boştu.
pub const GOVERNANCE_ADDRESS: &str = "0x0000000000000000000000000000000000000009";

/// `SlashValidator` hedefi, TEK kaynak: alıcı sentinel ise `payload`da, değilse
/// `receiver`. Yürütme, scheduler ve re-entrancy kilidi bunu çağırmalı (veri yarışı).
/// 🚨 Payload ABI kodlu ikili veridir; UTF-8 sanılırsa boş adrese düşerdi.
pub fn slash_target_address(receiver: &str, payload: &[u8]) -> Address {
    if receiver != SLASH_VALIDATOR_ADDRESS {
        return receiver.to_string();
    }
    // Geriye dönük uyumluluk: düz UTF-8 "0x..." metni ÖNCE denenir; ABI kodlu
    // ikili veri `validate_address`'i geçemez (seçicinin ilk baytı geçerli UTF-8
    // başlangıcı bile değil), iki biçim çakışmaz.
    if let Ok(text) = std::str::from_utf8(payload) {
        if Transaction::validate_address(text) {
            return text.to_string();
        }
    }
    // Standart ABI-kodlu `slash(address)` çağrısı: 4 baytlık seçici + adresin
    // son 20 baytta olduğu 32 baytlık sağa-hizalı bir kelime. GERÇEK tek
    // çağıranın (CommandView.tsx) ürettiği biçim budur.
    if payload.len() >= 36 {
        let word = &payload[4..36];
        return format!("0x{}", hex::encode(&word[12..32]));
    }
    // Seçicisiz, doğrudan 32 baytlık sağa-hizalı ABI kodlaması.
    if payload.len() == 32 {
        return format!("0x{}", hex::encode(&payload[12..32]));
    }
    // Ham 20 baytlık adres (kodlama yok).
    if payload.len() == 20 {
        return format!("0x{}", hex::encode(payload));
    }
    String::new()
}

// GAS CONSTANTS

/// 🛡️ Tek mint işleminin azami ZERENYA'sı (savunma derinliği, ~genesis
/// havuzunun %1'i); otomatik ölçeklenmez, operatör büyüdükçe gözden geçirmeli.
pub const MAX_SINGLE_BRIDGE_MINT: u128 = 100 * TOKEN_DECIMAL;

/// 🏛️ Token Factory harcı: yeni oluşan her kontrat için sabit hedef (ZERENYA);
/// ham ZAGROS tahsilat anında havuz oranından türetilir. $7.77 / $4.000 =
/// 0,0019425 ZERENYA olarak bir kez türetildi, sistemde dolar oracle'ı YOK.
pub const TOKEN_FACTORY_FEE_ZERENYA: u128 = 1_942_500_000_000_000; // 0.0019425 ZERENYA (~$7.77 eşdeğeri, $4.000/ons varsayımıyla)

// 🛡️ ANAYASA: sabit altın cinsinden gas hedefi (0,0000125 ZERENYA);
// `base_gas_fee_from_reserves` havuz oranıyla ham ZAGROS'a çevirir.
pub const GAS_FEE_ZERENYA: u128 = 12_500_000_000_000; // 0.0000125 ZERENYA = 0.388793 mg altın

// 🛡️ AĞ LİMİTLERİ (stabilite > hayali TPS). 5.000-10.000 TPS bir TASARIM
// HEDEFİ; ölçülen throughput README "Performance Benchmarks"ta. Kısıtlayan bu
// limitler değil, yürütme ve yayılım. Donanım gereksinimi 8 GB RAM.
pub const MAX_MEMPOOL_CAPACITY: usize = 100_000; // Maksimum Bekleyen İşlem. (Eski: 1.000.000)
pub const DDOS_THRESHOLD: usize = 50_000; // 50 Bin'den sonra üstel gas kalkanı vurur (Eski: 250.000)
                                          // 🛡️ K4: Mempool TOPLAM bellek bütçesi. Sadece işlem ADEDİ (MAX_MEMPOOL_CAPACITY)
                                          // değil, havuzdaki işlemlerin toplam bayt boyutu da sınırlanır, aksi halde bir
                                          // saldırgan 100.000 adet 128KB'lık ContractCall ile ~12.8GB RAM tüketebilirdi.
pub const MAX_MEMPOOL_TOTAL_BYTES: usize = 256 * 1024 * 1024; // 256 MB
pub const MAX_BLOCK_TX_LIMIT: usize = 10_000; // 🔥 BİR BLOKA GİRECEK MAKSİMUM İŞLEM (Elektronik Hız Sınırlayıcı)
pub const MAX_BLOCK_GAS_LIMIT: u128 = 100_000_000; // Opsiyonel EVM Gas Hacmi (100M Gas)

// 🔷 EVM DİNAMİK ANTI-DDOS GAS MODELİ: EVM işlemleri native sabit cetvelden
// muaf (cüzdanlar Ethereum ölçeğinde beyan eder); koruma intrinsic gas tabanı +
// üstel stres çarpanı, ücret `gas_used × gas_price` olarak Hazine'ye akar.

/// EIP-2028 taban intrinsic gas: her EVM işleminin ödemek zorunda olduğu sabit
/// çekirdek maliyet.
pub const EVM_INTRINSIC_GAS_BASE: u128 = 21_000;

/// Calldata'daki SIFIR baytın intrinsic gas maliyeti (EIP-2028).
pub const EVM_CALLDATA_GAS_ZERO: u128 = 4;

/// Calldata'daki sıfır OLMAYAN baytın intrinsic gas maliyeti (EIP-2028).
pub const EVM_CALLDATA_GAS_NONZERO: u128 = 16;

/// Asgari EVM gas fiyatı (1 gwei), anti-DDoS tabanının fiyat ayağı; stres
/// modunda 1024x'e kadar çarpılır.
pub const MIN_EVM_GAS_PRICE_WEI: u128 = 1_000_000_000;

/// 🏭 EVM deploy mu: boş `to` sıfır adres olur, revm `Create` yürütür, x100
/// harç. Tek ölçüt, iki tüketici. 🚨 Sıfır adres havuz adresi; yalnız EVM hattında anlamlı.
pub fn is_evm_deploy(receiver: &str) -> bool {
    receiver.is_empty()
        || receiver == "0x"
        || receiver == "0x0000000000000000000000000000000000000000"
}

// LIQUIDITY PROTECTION

/// 🚨 ZAGROS ve ZERENYA için AYRI tabanlar: tek eşik olsaydı ZERENYA
/// (genesis 10.500, ZAGROS'tan ~4000x küçük) hep tabanın altında kalır,
/// havuz kalıcı kilitlenir, hiçbir swap çalışmazdı.
pub const MIN_POOL_LIQUIDITY_ZAGROS: u128 = 1_000_000 * TOKEN_DECIMAL; // eski MIN_POOL_LIQUIDITY ile aynı değer

/// Genesis ZERENYA rezervinin (`GENESIS_POOL_ZERENYA` = 10.500) ~%2,4'ü,
/// `MIN_POOL_LIQUIDITY_ZAGROS`'un kendi genesis rezervine (42M) oranıyla
/// AYNI güvenlik marjı korunarak türetildi (1.000.000 / 42.000.000 ≈ %2,38).
pub const MIN_POOL_LIQUIDITY_ZERENYA: u128 = 250 * TOKEN_DECIMAL;

pub const MAX_SWAP_AMOUNT_PERCENT: u128 = 5; // Max 5% of pool per swap

// GENESIS ADDRESSES

pub const FOUNDER_ADDRESS: &str = "0x00000005668becb40d7eaafdae73ed6347932d49";
// Kurucu 0 likit ZAGROS alır (tüm arz havuzda). Kurucu genesis validatörüyse
// `staked_balance` ayrıca seed edilmeli, yoksa epoch 1'de Probation'a düşer.
pub const FOUNDER_GENESIS_ZAGROS: u128 = 0;
/// Kurucunun genesis ZERENYA'sı; havuzun 10.500'ünün aksine PAXG teminatı YOK,
/// açık pozisyon zincirde şeffaf gösterilmeli.
pub const FOUNDER_GENESIS_ZERENYA: u128 = 500 * TOKEN_DECIMAL;
// Köprü basımı 2/3 çoklu imza + kilit + günlük tavanla korunur; bu sabit
// yalnız `signer_secret_key_hex` boşken kullanılan yedek adres.
pub const BRIDGE_AUTHORITY_ADDRESS: &str = FOUNDER_ADDRESS;

// GOVERNANCE, TEMPORARY ADMIN

/// Kurucunun acil `SlashValidator` yetkisinin süresi; işaretçi yoksa dolmuş sayılır.
/// 2 yıl: erken dönemde tek araç; governance ile KISALTILABİLİR.
pub const ADMIN_AUTHORITY_PERIOD_SECONDS: u128 = 730 * 24 * 60 * 60;

/// Governance ile belirlenen ERKEN bitiş anı (unix sn). 🛡️ YALNIZCA KISALTIR:
/// yetki `genesis + süre` ile bu değerin küçüğünde biter, daha geç an yazılamaz.
/// Topluluk erken bitirebilir, kimse uzatamaz.
pub const ADMIN_AUTHORITY_END_KEY: &str = "__ADMIN_AUTHORITY_END__";

pub const GENESIS_TIMESTAMP_KEY: &str = "__GENESIS_TIMESTAMP__";

/// 🛡️ Sabit genesis zaman damgası (`block_0`a gömülür, blok 1 parent_hash'i).
/// Gerçek çıkış anı (1 Eylül 2026, 22:25 UTC); keyless deployer ve Multicall3 nonce taşımaz.
pub const GENESIS_TIMESTAMP: u128 = 1_788_301_500;

// TRANSACTION TYPES

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum TxType {
    /// Simple token transfer
    Transfer,

    /// DEX: Buy tokens from pool
    SwapBuy,

    /// DEX: Sell tokens to pool
    SwapSell,

    /// Bridge: Mint ZERENYA against a locked PAXG (gold) reserve on Ethereum
    BridgeMint,

    /// Bridge: Mint ZERENYA from a locked PAXG reserve and immediately swap to Zagros
    BridgeMintAndSwap,

    /// Bridge: Burn ZERENYA and unlock the backing PAXG on Ethereum
    BridgeBurn,

    /// Bridge: Swap Zagros to ZERENYA and burn the output
    BridgeSwapAndBurn,

    /// Staking: Lock Zagros tokens for rewards
    StakeZagros,

    /// Staking: Unlock staked tokens
    UnstakeZagros,

    /// Smart Contract: Deploy new contract
    DeployContract,

    /// Smart Contract: Call existing contract (legacy name, kept for compatibility)
    CallContract,

    /// Smart Contract: Execute contract with data payload (EVM-compatible)
    ContractCall {
        /// Contract call data payload
        data: Vec<u8>,
    },

    /// Governance: Submit proposal
    SubmitProposal,

    /// Governance: Vote on proposal
    Vote,

    /// Staking claim: withdraw accumulated rewards from the validator reward pool
    ClaimReward,

    /// Slashing: Execute emergency asset seizure from a misbehaving validator
    SlashValidator,

    /// Slashing: Report malicious validator
    ReportMalicious,

    /// Permissionless validator registration: requires staked_balance >=
    /// MIN_VALIDATOR_STAKE, not already registered, not jailed. Optional
    /// payload: 2-byte big-endian commission_bps (0-10000), empty = 0.
    RegisterValidator,

    /// Voluntary validator de-registration. Leaves staking/delegation
    /// untouched, only affects eligibility for the validator reward share.
    UnregisterValidator,

    /// G2 (CONSENSUS-SPEC §2): adayı onaylar. Faz A: payload 3-of-5 admin
    /// multisig imzaları (`consensus::AdminActionPayload`); Faz B: validator
    /// 2/3 quorum oyu (P1-5). Hedef adres payload'dadır (receiver = sentinel).
    ApproveValidator,

    /// G2 (§2): validator'ı kümeden çıkarır (Removed + bond lock). Yetki ve
    /// payload biçimi ApproveValidator ile aynı.
    RemoveValidator,

    /// G14 (§15): konsensüs anahtarı rotasyonu (`RotateConsensusKeyPayload`),
    /// sonraki epoch'ta etkin. ⚠️ Bincode: yeni varyant hep enum SONUNA.
    RotateConsensusKey,
}

impl fmt::Display for TxType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TxType::Transfer => write!(f, "Transfer"),
            TxType::SwapBuy => write!(f, "SwapBuy"),
            TxType::SwapSell => write!(f, "SwapSell"),
            TxType::BridgeMint => write!(f, "BridgeMint"),
            TxType::BridgeMintAndSwap => write!(f, "BridgeMintAndSwap"),
            TxType::BridgeBurn => write!(f, "BridgeBurn"),
            TxType::BridgeSwapAndBurn => write!(f, "BridgeSwapAndBurn"),
            TxType::StakeZagros => write!(f, "StakeZagros"),
            TxType::UnstakeZagros => write!(f, "UnstakeZagros"),
            TxType::DeployContract => write!(f, "DeployContract"),
            TxType::CallContract => write!(f, "CallContract"),
            TxType::ContractCall { .. } => write!(f, "ContractCall"),
            TxType::ClaimReward => write!(f, "ClaimReward"),
            TxType::SlashValidator => write!(f, "SlashValidator"),
            TxType::SubmitProposal => write!(f, "SubmitProposal"),
            TxType::Vote => write!(f, "Vote"),
            TxType::ReportMalicious => write!(f, "ReportMalicious"),
            TxType::RegisterValidator => write!(f, "RegisterValidator"),
            TxType::UnregisterValidator => write!(f, "UnregisterValidator"),
            TxType::ApproveValidator => write!(f, "ApproveValidator"),
            TxType::RemoveValidator => write!(f, "RemoveValidator"),
            TxType::RotateConsensusKey => write!(f, "RotateConsensusKey"),
        }
    }
}

// TRANSACTION STRUCTURE

#[derive(Debug, Clone)]
pub struct Transaction {
    /// Unique transaction identifier
    pub tx_id: Hash,

    /// Type of transaction
    pub tx_type: TxType,

    /// Sender address
    pub sender: Address,

    /// Amount to transfer (in smallest unit)
    pub amount: u128,

    /// Receiver address (or contract address)
    pub receiver: Address,

    /// Additional data (contract bytecode, call data, etc.)
    pub payload: Vec<u8>,

    /// Cryptographic signature
    pub signature: Signature,

    /// Unix timestamp in milliseconds
    pub timestamp: u128,

    /// Account nonce (prevents replay attacks)
    pub nonce: Nonce,

    /// Gas limit for this transaction
    pub gas_limit: u64,

    /// Gas price (in smallest unit)
    pub gas_price: u128,

    /// Chain identifier for replay protection
    pub chain_id: u64,
}

/// EVM kökenli bir işlemin imza dijestini HAM RLP'den türetir. İmza formatının
/// artık ayrıca bir sighash TAŞIMAMASINI mümkün kılan fonksiyon (bkz.
/// `verify_signature_production`'daki boyut optimizasyonu notu).
fn evm_sighash_from_raw_rlp(raw_rlp: &[u8]) -> Option<[u8; 32]> {
    use ethers_core::types::transaction::eip2718::TypedTransaction;
    use ethers_core::utils::rlp::Rlp;

    let rlp = Rlp::new(raw_rlp);
    let (typed_tx, _sig) = TypedTransaction::decode_signed(&rlp).ok()?;
    typed_tx.sighash().as_bytes().try_into().ok()
}

// İŞLEM TEL FORMATI: `Transaction` bellekte aynı, tele/depoya sıkıştırılmış
// (adres 21 bayt, LEB128, tx_type 1 bayt, türetilebilen `tx_id` taşınmaz).
// KANONİKLİK: non-minimal varint, dizgi adres, gereksiz `tx_id` REDDEDİLİR.

const TX_WIRE_VERSION: u8 = 1;

/// §23 (G10): sıkıştırılmış tel formatının devreye girdiği kural seti.
pub const TX_COMPACT_RULESET: u32 = 2;

/// Depo kayıtlarının sihirli öneki; konsensüs yolunda kullanılmaz (8 bayt blok
/// kapasitesinden çalar), depoda eski/yeni kayıt yan yana yaşadığından şart.
pub const TX_STORED_COMPACT_MAGIC: [u8; 8] = *b"ZGTXC002";

/// 🚨 KONSENSÜS KRİTİK: ikili yazım formatı zincirden türer (`active_ruleset`),
/// elle set ETME; epoch sınırında tüm node'lar aynı anda geçer (§23).
static TX_WIRE_RULESET: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

/// Zincirden okunan `active_ruleset`'i tel formatı anahtarına bağlar.
pub fn set_tx_wire_ruleset(ruleset: u32) {
    TX_WIRE_RULESET.store(ruleset, std::sync::atomic::Ordering::Relaxed);
}

pub fn tx_wire_ruleset() -> u32 {
    TX_WIRE_RULESET.load(std::sync::atomic::Ordering::Relaxed)
}

fn compact_wire_active() -> bool {
    tx_wire_ruleset() >= TX_COMPACT_RULESET
}

fn put_uvarint(out: &mut Vec<u8>, mut value: u128) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn get_uvarint(input: &mut &[u8]) -> std::result::Result<u128, &'static str> {
    let mut result: u128 = 0;
    let mut shift: u32 = 0;
    loop {
        let (&byte, rest) = input.split_first().ok_or("varint kesildi")?;
        *input = rest;
        let payload = u128::from(byte & 0x7f);
        if shift >= 128 || payload > (u128::MAX >> shift) {
            return Err("varint 128 bite sigmiyor");
        }
        result |= payload << shift;
        if byte & 0x80 == 0 {
            if byte == 0 && shift > 0 {
                return Err("kanonik olmayan varint (gereksiz devam bayti)");
            }
            return Ok(result);
        }
        shift += 7;
    }
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_uvarint(out, bytes.len() as u128);
    out.extend_from_slice(bytes);
}

fn get_bytes(input: &mut &[u8]) -> std::result::Result<Vec<u8>, &'static str> {
    let len = usize::try_from(get_uvarint(input)?).map_err(|_| "uzunluk usize'a sigmiyor")?;
    if input.len() < len {
        return Err("bayt dizisi kesildi");
    }
    let (raw, rest) = input.split_at(len);
    *input = rest;
    Ok(raw.to_vec())
}

/// `0x` + 40 KÜÇÜK harf hex ise 20 ham bayt. Büyük/karışık harfli (EIP-55
/// sağlama toplamlı) bir adres AYNEN korunmalı, `hash()` ve state anahtarları
/// dizginin kendisine bağlı, o yüzden onlar dizgi dalına düşer.
fn canonical_address_bytes(address: &str) -> Option<[u8; 20]> {
    let hex_part = address.strip_prefix("0x")?;
    if hex_part.len() != 40 {
        return None;
    }
    if !hex_part
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0u8; 20];
    hex::decode_to_slice(hex_part, &mut out).ok()?;
    Some(out)
}

fn put_address(out: &mut Vec<u8>, address: &str) {
    match canonical_address_bytes(address) {
        Some(raw) => {
            out.push(0);
            out.extend_from_slice(&raw);
        }
        None => {
            out.push(1);
            put_bytes(out, address.as_bytes());
        }
    }
}

fn get_address(input: &mut &[u8]) -> std::result::Result<String, &'static str> {
    let (&tag, rest) = input.split_first().ok_or("adres etiketi yok")?;
    *input = rest;
    match tag {
        0 => {
            if input.len() < 20 {
                return Err("adres 20 bayt degil");
            }
            let (raw, rest) = input.split_at(20);
            *input = rest;
            Ok(format!("0x{}", hex::encode(raw)))
        }
        1 => {
            let raw = get_bytes(input)?;
            let address = String::from_utf8(raw).map_err(|_| "adres UTF-8 degil")?;
            if canonical_address_bytes(&address).is_some() {
                return Err("kanonik olmayan adres kodlamasi (20 bayt dizgi olarak yazilmis)");
            }
            Ok(address)
        }
        _ => Err("bilinmeyen adres etiketi"),
    }
}

/// `TxType` → 1 bayt kod. Joker yok: yeni varyant derlemeyi kırar, kod bilinçli
/// seçilir. Kodlar KALICI, varyant sırası değişse de değişmez.
fn tx_type_code(tx_type: &TxType) -> u8 {
    match tx_type {
        TxType::Transfer => 0,
        TxType::SwapBuy => 1,
        TxType::SwapSell => 2,
        TxType::BridgeMint => 3,
        TxType::BridgeMintAndSwap => 4,
        TxType::BridgeBurn => 5,
        TxType::BridgeSwapAndBurn => 6,
        TxType::StakeZagros => 7,
        TxType::UnstakeZagros => 8,
        TxType::DeployContract => 9,
        TxType::CallContract => 10,
        TxType::ContractCall { .. } => 11,
        TxType::SubmitProposal => 12,
        TxType::Vote => 13,
        TxType::ClaimReward => 14,
        TxType::SlashValidator => 15,
        TxType::ReportMalicious => 16,
        TxType::RegisterValidator => 17,
        TxType::UnregisterValidator => 18,
        TxType::ApproveValidator => 19,
        TxType::RemoveValidator => 20,
        TxType::RotateConsensusKey => 21,
    }
}

fn put_tx_type(out: &mut Vec<u8>, tx_type: &TxType) {
    out.push(tx_type_code(tx_type));
    if let TxType::ContractCall { data } = tx_type {
        put_bytes(out, data);
    }
}

fn get_tx_type(input: &mut &[u8]) -> std::result::Result<TxType, &'static str> {
    let (&code, rest) = input.split_first().ok_or("tx_type kodu yok")?;
    *input = rest;
    Ok(match code {
        0 => TxType::Transfer,
        1 => TxType::SwapBuy,
        2 => TxType::SwapSell,
        3 => TxType::BridgeMint,
        4 => TxType::BridgeMintAndSwap,
        5 => TxType::BridgeBurn,
        6 => TxType::BridgeSwapAndBurn,
        7 => TxType::StakeZagros,
        8 => TxType::UnstakeZagros,
        9 => TxType::DeployContract,
        10 => TxType::CallContract,
        11 => TxType::ContractCall {
            data: get_bytes(input)?,
        },
        12 => TxType::SubmitProposal,
        13 => TxType::Vote,
        14 => TxType::ClaimReward,
        15 => TxType::SlashValidator,
        16 => TxType::ReportMalicious,
        17 => TxType::RegisterValidator,
        18 => TxType::UnregisterValidator,
        19 => TxType::ApproveValidator,
        20 => TxType::RemoveValidator,
        21 => TxType::RotateConsensusKey,
        _ => return Err("bilinmeyen tx_type kodu"),
    })
}

/// EVM-kökenli işlemlerde `tx_id`, imzanın sonuna gömülü HAM RLP'nin
/// keccak256'sıdır (Ethereum işlem hash'i; cüzdanlar ve dekontlar bu değeri
/// kullanır, `Transaction::hash()` DEĞİL). Bu yüzden taşınması gerekmez.
fn evm_tx_id(signature: &[u8]) -> Option<Hash> {
    if signature.len() <= 66 {
        return None;
    }
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    hasher.update(&signature[66..]);
    let digest = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&digest);
    Some(id)
}

const TXID_FROM_EVM_RLP: u8 = 0;
const TXID_FROM_HASH: u8 = 1;
const TXID_EXPLICIT: u8 = 2;

impl Transaction {
    /// Sıkıştırılmış tel/depo kodlaması. `bincode` bu crate dışındaki TÜM
    /// yollarda (blok gövdesi, gossip, arşiv kaydı) bunu kullanır.
    pub fn encode_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(320);
        out.push(TX_WIRE_VERSION);
        put_tx_type(&mut out, &self.tx_type);
        put_address(&mut out, &self.sender);
        put_address(&mut out, &self.receiver);
        put_uvarint(&mut out, self.amount);
        put_bytes(&mut out, &self.payload);
        put_bytes(&mut out, &self.signature);
        put_uvarint(&mut out, self.timestamp);
        put_uvarint(&mut out, u128::from(self.nonce));
        put_uvarint(&mut out, u128::from(self.gas_limit));
        put_uvarint(&mut out, self.gas_price);
        put_uvarint(&mut out, u128::from(self.chain_id));
        // `tx_id` EN SONDA: türetilebilmesi için diğer alanlar gerekli.
        if evm_tx_id(&self.signature) == Some(self.tx_id) {
            out.push(TXID_FROM_EVM_RLP);
        } else if self.hash() == self.tx_id {
            out.push(TXID_FROM_HASH);
        } else {
            out.push(TXID_EXPLICIT);
            out.extend_from_slice(&self.tx_id);
        }
        out
    }

    /// Arşiv/depo kaydı: sıkıştırılmış format sihirli önekle çerçevelenir ki
    /// yükseltme öncesi yazılmış ESKİ kayıtlar yükseltme sonrası da okunabilsin.
    pub fn to_stored_bytes(&self) -> std::result::Result<Vec<u8>, String> {
        if compact_wire_active() {
            let mut out = TX_STORED_COMPACT_MAGIC.to_vec();
            out.extend_from_slice(&self.encode_wire());
            Ok(out)
        } else {
            bincode::serialize(self).map_err(|e| format!("islem serilestirilemedi: {e}"))
        }
    }

    /// `to_stored_bytes`'ın tersi, iki formatı da okur: önekli kayıt önce
    /// sıkıştırılmış denenir, olmazsa eski düzen (bu yol okuma, konsensüs değil;
    /// önek tesadüfen eşleşse bile eski yola düşmek doğru).
    pub fn from_stored_bytes(bytes: &[u8]) -> std::result::Result<Self, String> {
        if bytes.len() > TX_STORED_COMPACT_MAGIC.len()
            && bytes[..TX_STORED_COMPACT_MAGIC.len()] == TX_STORED_COMPACT_MAGIC
        {
            if let Ok(tx) = Transaction::decode_wire(&bytes[TX_STORED_COMPACT_MAGIC.len()..]) {
                return Ok(tx);
            }
        }
        Self::decode_legacy_bincode(bytes)
    }

    /// Eski (alan alan bincode) düzen, bayraktan BAĞIMSIZ olarak.
    fn decode_legacy_bincode(bytes: &[u8]) -> std::result::Result<Self, String> {
        bincode::deserialize::<TransactionRepr>(bytes)
            .map(Transaction::from)
            .map_err(|e| format!("islem cozulemedi: {e}"))
    }

    /// `encode_wire`'ın tersi. Kanonik olmayan her kodlamayı reddeder.
    pub fn decode_wire(bytes: &[u8]) -> std::result::Result<Self, &'static str> {
        let mut input = bytes;
        let (&version, rest) = input.split_first().ok_or("bos islem")?;
        input = rest;
        if version != TX_WIRE_VERSION {
            return Err("bilinmeyen islem tel surumu");
        }
        let tx_type = get_tx_type(&mut input)?;
        let sender = get_address(&mut input)?;
        let receiver = get_address(&mut input)?;
        let amount = get_uvarint(&mut input)?;
        let payload = get_bytes(&mut input)?;
        let signature = get_bytes(&mut input)?;
        let timestamp = get_uvarint(&mut input)?;
        let nonce = u64::try_from(get_uvarint(&mut input)?).map_err(|_| "nonce u64'e sigmiyor")?;
        let gas_limit =
            u64::try_from(get_uvarint(&mut input)?).map_err(|_| "gas_limit u64'e sigmiyor")?;
        let gas_price = get_uvarint(&mut input)?;
        let chain_id =
            u64::try_from(get_uvarint(&mut input)?).map_err(|_| "chain_id u64'e sigmiyor")?;

        let (&id_tag, rest) = input.split_first().ok_or("tx_id etiketi yok")?;
        input = rest;

        let mut tx = Transaction {
            tx_id: [0u8; 32],
            tx_type,
            sender,
            amount,
            receiver,
            payload,
            signature,
            timestamp,
            nonce,
            gas_limit,
            gas_price,
            chain_id,
        };

        tx.tx_id = match id_tag {
            TXID_FROM_EVM_RLP => {
                evm_tx_id(&tx.signature).ok_or("EVM tx_id turetilemiyor (imza cok kisa)")?
            }
            TXID_FROM_HASH => {
                let derived = tx.hash();
                if evm_tx_id(&tx.signature) == Some(derived) {
                    return Err("kanonik olmayan tx_id etiketi (EVM dali kullanilmaliydi)");
                }
                derived
            }
            TXID_EXPLICIT => {
                if input.len() < 32 {
                    return Err("tx_id kesildi");
                }
                let (raw, rest) = input.split_at(32);
                input = rest;
                let mut id = [0u8; 32];
                id.copy_from_slice(raw);
                if evm_tx_id(&tx.signature) == Some(id) || tx.hash() == id {
                    return Err("kanonik olmayan tx_id (turetilebilirken acikca yazilmis)");
                }
                id
            }
            _ => return Err("bilinmeyen tx_id etiketi"),
        };

        if !input.is_empty() {
            return Err("islemin sonunda artik bayt var");
        }
        Ok(tx)
    }
}

/// JSON (ve diğer human-readable formatlar) için alan-alan ayna. `Transaction`
/// ile ALAN SIRASI ve İSİMLERİ birebir aynı olmalı.
#[derive(Serialize, Deserialize)]
#[serde(rename = "Transaction")]
struct TransactionRepr {
    tx_id: Hash,
    tx_type: TxType,
    sender: Address,
    amount: u128,
    receiver: Address,
    payload: Vec<u8>,
    signature: Signature,
    timestamp: u128,
    nonce: Nonce,
    gas_limit: u64,
    gas_price: u128,
    chain_id: u64,
}

impl From<&Transaction> for TransactionRepr {
    fn from(tx: &Transaction) -> Self {
        Self {
            tx_id: tx.tx_id,
            tx_type: tx.tx_type.clone(),
            sender: tx.sender.clone(),
            amount: tx.amount,
            receiver: tx.receiver.clone(),
            payload: tx.payload.clone(),
            signature: tx.signature.clone(),
            timestamp: tx.timestamp,
            nonce: tx.nonce,
            gas_limit: tx.gas_limit,
            gas_price: tx.gas_price,
            chain_id: tx.chain_id,
        }
    }
}

impl From<TransactionRepr> for Transaction {
    fn from(repr: TransactionRepr) -> Self {
        Self {
            tx_id: repr.tx_id,
            tx_type: repr.tx_type,
            sender: repr.sender,
            amount: repr.amount,
            receiver: repr.receiver,
            payload: repr.payload,
            signature: repr.signature,
            timestamp: repr.timestamp,
            nonce: repr.nonce,
            gas_limit: repr.gas_limit,
            gas_price: repr.gas_price,
            chain_id: repr.chain_id,
        }
    }
}

impl Serialize for Transaction {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        // İkili yolda format zincirden gelir: ruleset < 2 iken ESKİ düzen
        // (alan alan bincode) yazılır ki yeni binary eski zincirde çalışabilsin.
        if serializer.is_human_readable() || !compact_wire_active() {
            TransactionRepr::from(self).serialize(serializer)
        } else {
            serializer.serialize_bytes(&self.encode_wire())
        }
    }
}

impl<'de> Deserialize<'de> for Transaction {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        if deserializer.is_human_readable() || !compact_wire_active() {
            return TransactionRepr::deserialize(deserializer).map(Transaction::from);
        }

        struct WireVisitor;

        impl<'de> serde::de::Visitor<'de> for WireVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("sikistirilmis islem baytlari")
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> std::result::Result<Vec<u8>, E> {
                Ok(v.to_vec())
            }

            fn visit_byte_buf<E: serde::de::Error>(
                self,
                v: Vec<u8>,
            ) -> std::result::Result<Vec<u8>, E> {
                Ok(v)
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Vec<u8>, A::Error> {
                let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(320));
                while let Some(byte) = seq.next_element::<u8>()? {
                    out.push(byte);
                }
                Ok(out)
            }
        }

        let bytes = deserializer.deserialize_bytes(WireVisitor)?;
        Transaction::decode_wire(&bytes).map_err(serde::de::Error::custom)
    }
}

impl Transaction {
    /// Calculate transaction hash
    pub fn hash(&self) -> Hash {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();

        hasher.update(self.tx_type.to_string().as_bytes());
        hasher.update(self.sender.as_bytes());
        hasher.update(self.amount.to_le_bytes());
        hasher.update(self.receiver.as_bytes());
        hasher.update(&self.payload);
        hasher.update(self.timestamp.to_le_bytes());
        hasher.update(self.nonce.to_le_bytes());
        hasher.update(self.gas_limit.to_le_bytes());
        hasher.update(self.gas_price.to_le_bytes());
        hasher.update(self.chain_id.to_le_bytes());
        hasher.update(&self.signature);

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Verify transaction signature using Ethereum-style ECDSA recovery.
    pub fn verify_signature(&self) -> bool {
        self.verify_signature_production()
    }

    /// Sign this transaction with a secp256k1 secret key, producing the 65-byte
    /// recoverable ECDSA signature `verify_signature` expects. Callers must set
    /// `sender` to `Transaction::address_from_secret_key(secret_key)` beforehand.
    pub fn sign(&mut self, secret_key: &secp256k1::SecretKey) {
        use secp256k1::{Message, Secp256k1};

        let secp = Secp256k1::new();
        let message_hash = self.signing_message();
        let message = Message::from_digest_slice(&message_hash)
            .expect("signing_message always returns a 32-byte keccak256 digest");
        let recoverable_sig = secp.sign_ecdsa_recoverable(&message, secret_key);
        let (recovery_id, compact) = recoverable_sig.serialize_compact();

        let mut signature = Vec::with_capacity(65);
        signature.extend_from_slice(&compact);
        signature.push(recovery_id.to_i32() as u8);
        self.signature = signature;
    }

    /// EIP-155 imzalı EVM işleminden `Transaction` kurmanın TEK yolu.
    /// `signed_chain_id` RLP'den çıkarılan gerçek değer, `CHAIN_ID`ye karşı bağımsız doğrulanır.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_eip155(
        tx_id: Hash,
        tx_type: TxType,
        sender: Address,
        receiver: Address,
        amount: u128,
        payload: Vec<u8>,
        signature: Signature,
        timestamp: u128,
        nonce: Nonce,
        gas_limit: u64,
        gas_price: u128,
        signed_chain_id: u64,
    ) -> Result<Self> {
        if signed_chain_id != CHAIN_ID {
            return Err(ZagrosError::Other(format!(
                "chain_id uyuşmazlığı: işlem chain_id={} için imzalanmış, bu ağın chain_id'si {} \
                 (olası cross-chain replay, reddedildi)",
                signed_chain_id, CHAIN_ID
            )));
        }
        Ok(Self {
            tx_id,
            tx_type,
            sender,
            amount,
            receiver,
            payload,
            signature,
            timestamp,
            nonce,
            gas_limit,
            gas_price,
            chain_id: CHAIN_ID,
        })
    }

    /// Pre-EIP-155 işlemden `Transaction` kurmanın TEK yolu, yalnız keyless
    /// deployer için (replay zararsız); bağımsız ikinci savunma.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_keyless_deployment(
        tx_id: Hash,
        tx_type: TxType,
        sender: Address,
        receiver: Address,
        amount: u128,
        payload: Vec<u8>,
        signature: Signature,
        timestamp: u128,
        nonce: Nonce,
        gas_limit: u64,
        gas_price: u128,
    ) -> Result<Self> {
        if !is_keyless_deployer(&sender) {
            return Err(ZagrosError::Other(format!(
                "pre-EIP-155 (chain_id korumasız) imza yalnızca bilinen keyless deployer'lardan \
                 kabul edilir; gönderen {} listede değil - fail-closed reddedildi",
                sender
            )));
        }
        Ok(Self {
            tx_id,
            tx_type,
            sender,
            amount,
            receiver,
            payload,
            signature,
            timestamp,
            nonce,
            gas_limit,
            gas_price,
            chain_id: CHAIN_ID,
        })
    }

    /// Derive the Ethereum-style `0x...` address for a secp256k1 secret key.
    pub fn address_from_secret_key(secret_key: &secp256k1::SecretKey) -> Address {
        use secp256k1::{PublicKey, Secp256k1};
        use sha3::{Digest, Keccak256};

        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, secret_key);
        let pub_key_bytes = public_key.serialize_uncompressed();
        let mut hasher = Keccak256::new();
        hasher.update(&pub_key_bytes[1..]);
        let hash = hasher.finalize();
        format!("0x{}", hex::encode(&hash[12..]))
    }

    fn verify_signature_production(&self) -> bool {
        // EVM işlemi: `r||s||v || eth_type || ham_RLP`; sighash RLP'den türetilir.
        // 🚨 Ham RLP zorunlu, yalnız sighash alanları bağlamaz.
        if self.signature.len() > 66 {
            // 🚨 BOYUT: `sighash` taşınmaz, RLP'den türetilir (işlem başına 32 bayt);
            // güvenlik aynı, taşınan kopya sıfır bilgi içerirdi. `eth_type` korunur
            // (RPC `"type"` alanı). 256 KB blok tavanında her bayt kapasitedir.
            let raw_rlp = &self.signature[66..];
            let Some(sighash) = evm_sighash_from_raw_rlp(raw_rlp) else {
                return false;
            };
            let sender_ok = match recover_signer_address(&sighash, &self.signature[0..65]) {
                Some(recovered) => recovered.eq_ignore_ascii_case(&self.sender),
                None => false,
            };
            return sender_ok && self.verify_evm_field_binding(&sighash, raw_rlp);
        }

        let message_hash = self.signing_message();
        let message_hash: [u8; 32] = match message_hash.as_slice().try_into() {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };

        match recover_signer_address(&message_hash, &self.signature) {
            Some(recovered) => recovered.eq_ignore_ascii_case(&self.sender),
            None => false,
        }
    }

    /// 🚨 EVM işleminin alanlarının imzalanan RLP'den türediğini doğrular
    /// (RPC'yi atlayan yollar için). `gas_limit`/`gas_price` karşılaştırılmaz
    /// (mempool normalize eder), `timestamp` RLP'de yok.
    fn verify_evm_field_binding(&self, sighash: &[u8], raw_rlp: &[u8]) -> bool {
        use ethers_core::types::transaction::eip2718::TypedTransaction;
        use ethers_core::utils::rlp::Rlp;

        let rlp = Rlp::new(raw_rlp);
        let Ok((typed_tx, _sig)) = TypedTransaction::decode_signed(&rlp) else {
            return false;
        };

        // 1) Taşınan sighash GERÇEKTEN bu RLP'nin imza dijesti mi?
        if typed_tx.sighash().as_bytes() != sighash {
            return false;
        }

        // 2) chain_id (cross-chain replay). Pre-EIP-155 keyless deploy'larda
        // chain_id YOK; kurulum tarafındaki aynı istisna (`from_verified_keyless_deployment`)
        // yalnız izin listesindeki deployer'lar için uygulanır.
        match typed_tx.chain_id() {
            Some(c) if c.as_u64() == self.chain_id => {}
            None if is_keyless_deployer(&self.sender) => {}
            _ => return false,
        }

        // 3) nonce
        let signed_nonce = match typed_tx.nonce() {
            Some(n) if n.bits() <= 64 => n.as_u64(),
            _ => return false,
        };
        if signed_nonce != self.nonce {
            return false;
        }

        // 4) receiver (`to` yoksa sıfır adres, `decode_and_convert_tx` ile aynı)
        let signed_receiver = match typed_tx.to() {
            Some(ethers_core::types::NameOrAddress::Address(a)) => {
                format!("0x{}", hex::encode(a.as_bytes()))
            }
            Some(_) => return false,
            None => "0x0000000000000000000000000000000000000000".to_string(),
        };
        if !signed_receiver.eq_ignore_ascii_case(&self.receiver) {
            return false;
        }

        // 5) tx_type / amount / payload: kurulumla AYNI türetme kuralları
        let data: Vec<u8> = typed_tx.data().map(|d| d.to_vec()).unwrap_or_default();
        let signed_value = match typed_tx.value() {
            Some(v) if v.bits() <= 128 => v.as_u128(),
            Some(_) => return false,
            None => 0,
        };
        let (expected_type, expected_amount, expected_payload) = derive_native_call(
            &signed_receiver,
            &data,
            signed_value,
            typed_tx.to().is_none(),
        );

        expected_type == self.tx_type
            && expected_amount == self.amount
            && expected_payload == self.payload
    }

    /// Get the message that should be signed
    fn signing_message(&self) -> Vec<u8> {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();

        hasher.update(self.tx_type.to_string().as_bytes());
        hasher.update(self.sender.as_bytes());
        hasher.update(self.amount.to_le_bytes());
        hasher.update(self.receiver.as_bytes());
        hasher.update(&self.payload);
        hasher.update(self.timestamp.to_le_bytes());
        hasher.update(self.nonce.to_le_bytes());
        hasher.update(self.gas_limit.to_le_bytes());
        hasher.update(self.gas_price.to_le_bytes());
        hasher.update(self.chain_id.to_le_bytes());

        hasher.finalize().to_vec()
    }
    /// Validate address format.
    /// Supported formats:
    /// - 0x + 40 hex characters = 42 total
    pub fn validate_address(address: &str) -> bool {
        if address.starts_with("0x") || address.starts_with("0X") {
            if address.len() != 42 {
                return false;
            }
            return address[2..].chars().all(|c| c.is_ascii_hexdigit());
        }

        false
    }

    /// Validate transaction fields
    pub fn validate(&self) -> Result<()> {
        // Cryptographic signature must match the claimed sender before anything else runs.
        if !self.verify_signature() {
            return Err(ZagrosError::InvalidSignature);
        }

        // Validate sender address
        if !Self::validate_address(&self.sender) {
            return Err(ZagrosError::InvalidAddress);
        }

        // Validate receiver address
        if !Self::validate_address(&self.receiver) {
            return Err(ZagrosError::InvalidAddress);
        }

        // Validate chain ID for replay protection
        if self.chain_id != CHAIN_ID {
            return Err(ZagrosError::Other("Invalid Chain ID".to_string()));
        }

        // Validate amount for transfer types
        if matches!(
            self.tx_type,
            TxType::Transfer
                | TxType::SwapBuy
                | TxType::SwapSell
                | TxType::StakeZagros
                | TxType::UnstakeZagros
        ) {
            // 🛡️ amount==0 reddi: sıfır tutarlı işlem no-op, nonce ve blok alanı
            // israfı. 🚨 `UnstakeZagros` DIŞINDA: 0 onun için "kilidi dolmuş bekleyen
            // çekimi aktar" anlamına gelir (dApp "Varlıkları Çek" amount=0 gönderir).
            if self.amount == 0 && !matches!(self.tx_type, TxType::UnstakeZagros) {
                return Err(ZagrosError::Other(
                    "Amount must be greater than zero".to_string(),
                ));
            }
            // Check for unreasonably large amounts (> total supply)
            if self.amount > TOTAL_SUPPLY {
                return Err(ZagrosError::Other(
                    "Amount exceeds total supply".to_string(),
                ));
            }
        }

        // Validate ContractCall has data payload
        if let TxType::ContractCall { data } = &self.tx_type {
            if data.is_empty() {
                return Err(ZagrosError::Other(
                    "ContractCall must have non-empty data payload".to_string(),
                ));
            }
        }

        // Validate gas limit
        if self.gas_limit == 0 {
            return Err(ZagrosError::Other("Gas limit cannot be zero".to_string()));
        }

        // Validate gas limit is reasonable (max 10M gas)
        if self.gas_limit > 10_000_000 {
            return Err(ZagrosError::GasLimitExceeded);
        }

        // Validate gas price
        if self.gas_price == 0 {
            return Err(ZagrosError::Other("Gas price cannot be zero".to_string()));
        }

        // Validate payload size (max 1MB)
        if self.payload.len() > 1_048_576 {
            return Err(ZagrosError::Other(
                "Payload too large (max 1MB)".to_string(),
            ));
        }

        Ok(())
    }
}

// ACCOUNT STATE

// 🚨 DOĞRUDAN YENİ ALAN EKLEMEYİN: bincode kendini tanımlamaz, eski kayıt
// okunamaz ve tüm ağ restart'ta kilitlenir. Yeni alan: `AccountStateV{N}` + `From` + göç zinciri + test.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccountState {
    /// Zagros token balance
    pub balance: Balance,

    /// ZERENYA (1 ZERENYA = 1 troy ons altın, PAXG ile 1:1 köprü teminatlı) bakiyesi
    pub zerenya_balance: Balance,

    /// Staked Zagros balance (locked)
    pub staked_balance: Balance,

    /// Reward debt for accumulated reward-per-share accounting
    pub reward_debt: u128,

    /// Is this a smart contract?
    pub is_contract: bool,

    /// Contract bytecode (WASM or EVM)
    pub contract_code: Vec<u8>,

    /// Contract storage mapping for EVM state
    pub storage: BTreeMap<U256, U256>,

    /// Account nonce (transaction counter)
    pub nonce: Nonce,

    /// Contract storage root hash
    pub storage_root: Hash,

    /// ⏳ YENİ: 48 Saatlik Zaman Kilidi Kasası
    pub pending_unstake_amount: u128,
    pub unlock_time: u128,

    /// 🏛️ Permissionless validator kaydı, `staked_balance >= MIN_VALIDATOR_STAKE`
    /// TEK BAŞINA validator yapmaz, `RegisterValidator` işlemiyle açık onay şart
    /// (bkz. `TxType::RegisterValidator`).
    pub is_registered_validator: bool,
    /// Slash edilen bir validator, bu zaman damgasına kadar YENİDEN kayıt
    /// olamaz (taze sermayeyle anında geri dönüşü engeller). 0 = hapiste değil.
    pub jailed_until: u128,
    /// ⏳ Anti-flash-stake kasası: yeni stake aktivasyon zamanı geçmeden ödül
    /// muhasebesine katılmaz (`settle_pending_stake`).
    pub pending_stake_amount: u128,
    pub pending_stake_activation_time: u128,

    /// 🏛️ Son `RegisterValidator` blok zaman damgası (0 = hiç kayıt yok ya da
    /// alan öncesi migration; UI "N/A" göstermeli, "genesis" değil).
    /// `UnregisterValidator` sıfırlamaz, yeniden kayıtta güncellenir.
    pub validator_registered_at: u128,

    // ---- G2: validator lifecycle alanları (önceki şekil `AccountStateV3`) ----
    /// Lifecycle durumu (§2); `None` = kayıt yok, `is_registered_validator` senkron tutulur.
    pub validator_status: Option<crate::consensus::ValidatorStatus>,
    /// Epoch için geçerli Ed25519 konsensüs anahtarı (hesap anahtarından AYRI).
    pub consensus_pubkey: [u8; 32],
    /// Onboarding beyanları (provider/region/asn/operator), tavanlar zincir-üstü.
    pub validator_declaration: crate::consensus::ValidatorDeclaration,
    /// Kayıt anındaki min-stake snapshot'ı (ZAGROS ham birim); niteliklilik
    /// kontrolü bu değere `stake_hysteresis_bps` toleransı uygular (§13.3).
    pub validator_stake_snapshot: u128,
    /// Son durum değişikliğinin epoch'u (probation başlangıcı vb.).
    pub validator_status_epoch: u64,
    /// Liveness/uptime sayaçları (§11.4), P0-7'de doldurulur.
    pub liveness: crate::consensus::LivenessCounters,
    /// Exiting/Removed sonrası teminatın kilitli kaldığı an (saniye); kilitteyken
    /// slash edilebilir (§11.5, `bond_lock_seconds`).
    pub bond_unlock_at: u128,
}

impl AccountState {
    /// Create new account with initial balance
    pub fn new(balance: Balance) -> Self {
        Self {
            balance,
            pending_unstake_amount: 0,
            unlock_time: 0,
            ..Default::default()
        }
    }

    /// Create new contract account
    pub fn new_contract(code: Vec<u8>) -> Self {
        Self {
            is_contract: true,
            contract_code: code,
            ..Default::default()
        }
    }

    /// 🏛️ `accumulated_reward_per_share` ayrı ham anahtarda değil, 0x0 sistem
    /// hesabının depolama slot 0'ında tutulur; böylece Merkle `state_root`
    /// kapsamına girer (0x0'ın depolaması başka yerde kullanılmaz).
    fn reward_acc_storage_slot() -> U256 {
        U256::ZERO
    }

    /// Ödül akümülatörünü bu hesabın depolama slot'undan okur (yoksa 0).
    pub fn get_reward_per_share(&self) -> u128 {
        self.storage
            .get(&Self::reward_acc_storage_slot())
            .and_then(|v| u128::try_from(*v).ok())
            .unwrap_or(0)
    }

    /// Ödül akümülatörünü bu hesabın depolama slot'una yazar.
    pub fn set_reward_per_share(&mut self, amount: u128) {
        self.storage
            .insert(Self::reward_acc_storage_slot(), U256::from(amount));
    }

    /// Get total balance (liquid + staked)
    pub fn total_balance(&self) -> Balance {
        self.balance.saturating_add(self.staked_balance)
    }

    /// Increment nonce
    pub fn increment_nonce(&mut self) {
        self.nonce = self.nonce.saturating_add(1);
    }

    /// Safely add to balance (with overflow check)
    pub fn add_balance(&mut self, amount: Balance) -> Result<()> {
        self.balance = self
            .balance
            .checked_add(amount)
            .ok_or(ZagrosError::Other("Balance overflow".to_string()))?;
        Ok(())
    }

    /// Safely subtract from balance (with underflow check)
    pub fn sub_balance(&mut self, amount: Balance) -> Result<()> {
        self.balance = self
            .balance
            .checked_sub(amount)
            .ok_or(ZagrosError::InsufficientBalance)?;
        Ok(())
    }

    /// Safely add to ZERENYA balance
    pub fn add_zerenya_balance(&mut self, amount: Balance) -> Result<()> {
        self.zerenya_balance = self
            .zerenya_balance
            .checked_add(amount)
            .ok_or(ZagrosError::Other("ZERENYA balance overflow".to_string()))?;
        Ok(())
    }

    /// Safely subtract from ZERENYA balance
    pub fn sub_zerenya_balance(&mut self, amount: Balance) -> Result<()> {
        if self.zerenya_balance < amount {
            tracing::error!(
                "🚨 ZERENYA Bakiye Kontrolü Patladı! İstenen: {}, Mevcut ZERENYA: {}",
                amount,
                self.zerenya_balance
            );
        }
        self.zerenya_balance = self
            .zerenya_balance
            .checked_sub(amount)
            .ok_or(ZagrosError::InsufficientBalance)?;
        Ok(())
    }

    /// Diskten `AccountState` okur: önce güncel şekil, olmazsa eski şekiller
    /// (`AccountStateV0`...) denenir; hepsi başarısızsa GERÇEK bozulma, hata
    /// yukarı fırlatılır (fail-closed, varsayılan hesap UYDURULMAZ).
    pub fn deserialize_with_migration(bytes: &[u8]) -> std::result::Result<Self, String> {
        if let Ok(account) = bincode::deserialize::<AccountState>(bytes) {
            return Ok(account);
        }
        if let Ok(account) = bincode::deserialize::<AccountStateV4>(bytes) {
            return Ok(AccountState::from(account));
        }
        if let Ok(account) = bincode::deserialize::<AccountStateV3>(bytes) {
            return Ok(AccountState::from(account));
        }
        if let Ok(account) = bincode::deserialize::<AccountStateV2>(bytes) {
            return Ok(AccountState::from(account));
        }
        if let Ok(account) = bincode::deserialize::<AccountStateV1>(bytes) {
            return Ok(AccountState::from(account));
        }
        bincode::deserialize::<AccountStateV0>(bytes)
            .map(AccountState::from)
            .map_err(|e| {
                format!(
                    "AccountState deserialize edilemedi (güncel, V4, V3, V2, V1 VE V0 şekli denendi): {}",
                    e
                )
            })
    }
}

/// Yalnız eski disk kayıtları için (V4, G13 öncesi: `delegated_to` +
/// `validator_commission_bps` henüz sökülmemiş); yeni kod kullanmamalı.
/// Göçte iki alan düşürülür (tüketicisi yoktu).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct AccountStateV4 {
    /// Zagros token balance
    pub balance: Balance,

    /// ZERENYA (1 ZERENYA = 1 troy ons altın, PAXG ile 1:1 köprü teminatlı) bakiyesi
    pub zerenya_balance: Balance,

    /// Staked Zagros balance (locked)
    pub staked_balance: Balance,

    /// Reward debt for accumulated reward-per-share accounting
    pub reward_debt: u128,
    pub delegated_to: Address,

    /// Is this a smart contract?
    pub is_contract: bool,

    /// Contract bytecode (WASM or EVM)
    pub contract_code: Vec<u8>,

    /// Contract storage mapping for EVM state
    pub storage: BTreeMap<U256, U256>,

    /// Account nonce (transaction counter)
    pub nonce: Nonce,

    /// Contract storage root hash
    pub storage_root: Hash,

    /// ⏳ YENİ: 48 Saatlik Zaman Kilidi Kasası
    pub pending_unstake_amount: u128,
    pub unlock_time: u128,

    /// 🏛️ Permissionless validator kaydı, `staked_balance >= MIN_VALIDATOR_STAKE`
    /// TEK BAŞINA validator yapmaz, `RegisterValidator` işlemiyle açık onay şart
    /// (bkz. `TxType::RegisterValidator`).
    pub is_registered_validator: bool,
    /// Slash edilen bir validator, bu zaman damgasına kadar YENİDEN kayıt
    /// olamaz (taze sermayeyle anında geri dönüşü engeller). 0 = hapiste değil.
    pub jailed_until: u128,
    pub validator_commission_bps: u16,
    /// ⏳ Anti-flash-stake kasası: yeni stake aktivasyon zamanı geçmeden ödül
    /// muhasebesine katılmaz.
    pub pending_stake_amount: u128,
    pub pending_stake_activation_time: u128,

    /// 🏛️ Son `RegisterValidator` blok zaman damgası (0 = hiç kayıt yok ya da
    /// alan öncesi migration; UI "N/A" göstermeli).
    pub validator_registered_at: u128,

    // ---- CONSENSUS-SPEC v0.2 (G2): validator lifecycle alanları ----
    /// Lifecycle durumu (§2). `None` = kayıt yok; `is_registered_validator` senkron tutulur.
    pub validator_status: Option<crate::consensus::ValidatorStatus>,
    /// Epoch için geçerli Ed25519 konsensüs anahtarı (hesap anahtarından AYRI).
    pub consensus_pubkey: [u8; 32],
    /// Onboarding beyanları (provider/region/asn/operator), tavanlar zincir-üstü.
    pub validator_declaration: crate::consensus::ValidatorDeclaration,
    /// Kayıt anındaki min-stake snapshot'ı (ZAGROS ham birim); niteliklilik
    /// kontrolü bu değere `stake_hysteresis_bps` toleransı uygular (§13.3).
    pub validator_stake_snapshot: u128,
    /// Son durum değişikliğinin epoch'u (probation başlangıcı vb.).
    pub validator_status_epoch: u64,
    /// Liveness/uptime sayaçları (§11.4), P0-7'de doldurulur.
    pub liveness: crate::consensus::LivenessCounters,
    /// Exiting/Removed sonrası teminatın kilitli kaldığı an (saniye); kilitteyken
    /// slash edilebilir (§11.5, `bond_lock_seconds`).
    pub bond_unlock_at: u128,
}

impl From<AccountStateV4> for AccountState {
    fn from(old: AccountStateV4) -> Self {
        AccountState {
            balance: old.balance,
            zerenya_balance: old.zerenya_balance,
            staked_balance: old.staked_balance,
            reward_debt: old.reward_debt,
            is_contract: old.is_contract,
            contract_code: old.contract_code,
            storage: old.storage,
            nonce: old.nonce,
            storage_root: old.storage_root,
            pending_unstake_amount: old.pending_unstake_amount,
            unlock_time: old.unlock_time,
            is_registered_validator: old.is_registered_validator,
            jailed_until: old.jailed_until,
            pending_stake_amount: old.pending_stake_amount,
            pending_stake_activation_time: old.pending_stake_activation_time,
            validator_registered_at: old.validator_registered_at,
            validator_status: old.validator_status,
            consensus_pubkey: old.consensus_pubkey,
            validator_declaration: old.validator_declaration,
            validator_stake_snapshot: old.validator_stake_snapshot,
            validator_status_epoch: old.validator_status_epoch,
            liveness: old.liveness,
            bond_unlock_at: old.bond_unlock_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccountStateV0 {
    balance: Balance,
    zerenya_balance: Balance,
    staked_balance: Balance,
    reward_debt: u128,
    delegated_to: Address,
    is_contract: bool,
    contract_code: Vec<u8>,
    storage: BTreeMap<U256, U256>,
    nonce: Nonce,
    storage_root: Hash,
}

impl From<AccountStateV0> for AccountState {
    fn from(old: AccountStateV0) -> Self {
        AccountState {
            balance: old.balance,
            zerenya_balance: old.zerenya_balance,
            staked_balance: old.staked_balance,
            reward_debt: old.reward_debt,
            is_contract: old.is_contract,
            contract_code: old.contract_code,
            storage: old.storage,
            nonce: old.nonce,
            storage_root: old.storage_root,
            pending_unstake_amount: 0,
            unlock_time: 0,
            is_registered_validator: false,
            jailed_until: 0,
            pending_stake_amount: 0,
            pending_stake_activation_time: 0,
            validator_registered_at: 0,
            ..Default::default()
        }
    }
}

/// Validator kayıt/hapis/hakediş alanları öncesi şekil; yalnız göç için, yeni kod kullanmamalı.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccountStateV1 {
    balance: Balance,
    zerenya_balance: Balance,
    staked_balance: Balance,
    reward_debt: u128,
    delegated_to: Address,
    is_contract: bool,
    contract_code: Vec<u8>,
    storage: BTreeMap<U256, U256>,
    nonce: Nonce,
    storage_root: Hash,
    pending_unstake_amount: u128,
    unlock_time: u128,
}

impl From<AccountStateV1> for AccountState {
    fn from(old: AccountStateV1) -> Self {
        AccountState {
            balance: old.balance,
            zerenya_balance: old.zerenya_balance,
            staked_balance: old.staked_balance,
            reward_debt: old.reward_debt,
            is_contract: old.is_contract,
            contract_code: old.contract_code,
            storage: old.storage,
            nonce: old.nonce,
            storage_root: old.storage_root,
            pending_unstake_amount: old.pending_unstake_amount,
            unlock_time: old.unlock_time,
            is_registered_validator: false,
            jailed_until: 0,
            pending_stake_amount: 0,
            pending_stake_activation_time: 0,
            validator_registered_at: 0,
            ..Default::default()
        }
    }
}

/// `validator_registered_at` öncesi şekil; yalnız göç için, yeni kod kullanmamalı.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccountStateV2 {
    balance: Balance,
    zerenya_balance: Balance,
    staked_balance: Balance,
    reward_debt: u128,
    delegated_to: Address,
    is_contract: bool,
    contract_code: Vec<u8>,
    storage: BTreeMap<U256, U256>,
    nonce: Nonce,
    storage_root: Hash,
    pending_unstake_amount: u128,
    unlock_time: u128,
    is_registered_validator: bool,
    jailed_until: u128,
    validator_commission_bps: u16,
    pending_stake_amount: u128,
    pending_stake_activation_time: u128,
}

impl From<AccountStateV2> for AccountState {
    fn from(old: AccountStateV2) -> Self {
        AccountState {
            balance: old.balance,
            zerenya_balance: old.zerenya_balance,
            staked_balance: old.staked_balance,
            reward_debt: old.reward_debt,
            is_contract: old.is_contract,
            contract_code: old.contract_code,
            storage: old.storage,
            nonce: old.nonce,
            storage_root: old.storage_root,
            pending_unstake_amount: old.pending_unstake_amount,
            unlock_time: old.unlock_time,
            is_registered_validator: old.is_registered_validator,
            jailed_until: old.jailed_until,
            pending_stake_amount: old.pending_stake_amount,
            pending_stake_activation_time: old.pending_stake_activation_time,
            validator_registered_at: 0,
            ..Default::default()
        }
    }
}

/// G2 (lifecycle alanları) eklenmeden ÖNCEKİ `AccountState` şekli (V3 =
/// `validator_registered_at`'lı hal). YALNIZCA `deserialize_with_migration`
/// için var, yeni kod bunu doğrudan KULLANMAMALI.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccountStateV3 {
    balance: Balance,
    zerenya_balance: Balance,
    staked_balance: Balance,
    reward_debt: u128,
    delegated_to: Address,
    is_contract: bool,
    contract_code: Vec<u8>,
    storage: BTreeMap<U256, U256>,
    nonce: Nonce,
    storage_root: Hash,
    pending_unstake_amount: u128,
    unlock_time: u128,
    is_registered_validator: bool,
    jailed_until: u128,
    validator_commission_bps: u16,
    pending_stake_amount: u128,
    pending_stake_activation_time: u128,
    validator_registered_at: u128,
}

impl From<AccountStateV3> for AccountState {
    fn from(old: AccountStateV3) -> Self {
        AccountState {
            balance: old.balance,
            zerenya_balance: old.zerenya_balance,
            staked_balance: old.staked_balance,
            reward_debt: old.reward_debt,
            is_contract: old.is_contract,
            contract_code: old.contract_code,
            storage: old.storage,
            nonce: old.nonce,
            storage_root: old.storage_root,
            pending_unstake_amount: old.pending_unstake_amount,
            unlock_time: old.unlock_time,
            // Eski kayıtlı validator → lifecycle'da Candidate sayılır (onay yok);
            // konsensüs anahtarı/beyanı olmadığından Active olamaz.
            validator_status: if old.is_registered_validator {
                Some(crate::consensus::ValidatorStatus::Candidate)
            } else {
                None
            },
            is_registered_validator: old.is_registered_validator,
            jailed_until: old.jailed_until,
            pending_stake_amount: old.pending_stake_amount,
            pending_stake_activation_time: old.pending_stake_activation_time,
            validator_registered_at: old.validator_registered_at,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod account_state_migration_tests {
    use super::*;

    /// G2: V3 (lifecycle alanları öncesi) kaydı göç eder; kayıtlı validator
    /// Candidate olur, yeni alanlar varsayılan.
    #[test]
    fn v3_account_state_without_lifecycle_fields_still_deserializes() {
        let legacy = AccountStateV3 {
            balance: 7,
            zerenya_balance: 8,
            staked_balance: 9,
            reward_debt: 1,
            delegated_to: "0x0000000000000000000000000000000000000002".to_string(),
            is_contract: false,
            contract_code: vec![],
            storage: BTreeMap::new(),
            nonce: 3,
            storage_root: [0u8; 32],
            pending_unstake_amount: 4,
            unlock_time: 5,
            is_registered_validator: true,
            jailed_until: 6,
            validator_commission_bps: 250,
            pending_stake_amount: 10,
            pending_stake_activation_time: 11,
            validator_registered_at: 12,
        };
        let bytes = bincode::serialize(&legacy).unwrap();
        assert!(
            bincode::deserialize::<AccountState>(&bytes).is_err(),
            "guncel sekil dogrudan okuyamaz"
        );
        let migrated = AccountState::deserialize_with_migration(&bytes).unwrap();
        assert_eq!(migrated.balance, 7);
        assert_eq!(migrated.validator_registered_at, 12);
        assert!(migrated.is_registered_validator);
        assert_eq!(
            migrated.validator_status,
            Some(crate::consensus::ValidatorStatus::Candidate)
        );
        assert_eq!(migrated.consensus_pubkey, [0u8; 32]);
        assert_eq!(migrated.bond_unlock_at, 0);
        assert_eq!(
            migrated.liveness,
            crate::consensus::LivenessCounters::default()
        );
        // güncel şekil round-trip
        let again = bincode::serialize(&migrated).unwrap();
        assert_eq!(
            AccountState::deserialize_with_migration(&again)
                .unwrap()
                .staked_balance,
            9
        );
    }

    /// 🛡️ `pending_unstake_*` eklenmeden önce yazılmış kayıt hâlâ okunmalı;
    /// yerel `LegacyMirror` KASITLI olarak `AccountStateV0`'a referans vermez
    /// (bincode pozisyonel, aynı alan sırası aynı baytları üretir).
    #[test]
    fn old_account_state_without_unstake_fields_still_deserializes() {
        #[derive(Serialize, Deserialize)]
        struct LegacyMirror {
            balance: Balance,
            zerenya_balance: Balance,
            staked_balance: Balance,
            reward_debt: u128,
            delegated_to: Address,
            is_contract: bool,
            contract_code: Vec<u8>,
            storage: BTreeMap<U256, U256>,
            nonce: Nonce,
            storage_root: Hash,
        }

        let legacy_bytes = bincode::serialize(&LegacyMirror {
            balance: 42_000,
            zerenya_balance: 7_000,
            staked_balance: 1_000,
            reward_debt: 5,
            delegated_to: "0x1111111111111111111111111111111111111111".to_string(),
            is_contract: false,
            contract_code: vec![],
            storage: BTreeMap::new(),
            nonce: 3,
            storage_root: [9u8; 32],
        })
        .unwrap();

        // Güncel şekille DOĞRUDAN deserialize etmeye çalışmak (migration
        // olmadan) başarısız OLMALI, aksi halde bu test hiçbir şey kanıtlamaz.
        assert!(
            bincode::deserialize::<AccountState>(&legacy_bytes).is_err(),
            "bu test eski baytların GÜNCEL şekille zaten uyumlu olmadığını varsayıyor"
        );

        let migrated = AccountState::deserialize_with_migration(&legacy_bytes)
            .expect("eski (unstake alanları olmayan) hesap kaydı okunabilmeli");

        assert_eq!(migrated.balance, 42_000);
        assert_eq!(migrated.zerenya_balance, 7_000);
        assert_eq!(migrated.staked_balance, 1_000);
        assert_eq!(migrated.nonce, 3);
        assert_eq!(migrated.pending_unstake_amount, 0);
        assert_eq!(migrated.unlock_time, 0);
    }

    /// Güncel şekille yazılmış bir kayıt migration'a hiç uğramadan (hızlı yol)
    /// doğru okunmalı.
    #[test]
    fn current_account_state_round_trips_without_migration() {
        let account = AccountState {
            balance: 1,
            pending_unstake_amount: 99,
            unlock_time: 12345,
            ..Default::default()
        };
        let bytes = bincode::serialize(&account).unwrap();
        let read_back = AccountState::deserialize_with_migration(&bytes).unwrap();
        assert_eq!(read_back.pending_unstake_amount, 99);
        assert_eq!(read_back.unlock_time, 12345);
    }

    /// Validator alanları öncesi kayıt okunabilmeli, yeni alanlar güvenli varsayılanla dolmalı.
    #[test]
    fn v1_account_state_without_validator_fields_still_deserializes() {
        #[derive(Serialize, Deserialize)]
        struct LegacyMirrorV1 {
            balance: Balance,
            zerenya_balance: Balance,
            staked_balance: Balance,
            reward_debt: u128,
            delegated_to: Address,
            is_contract: bool,
            contract_code: Vec<u8>,
            storage: BTreeMap<U256, U256>,
            nonce: Nonce,
            storage_root: Hash,
            pending_unstake_amount: u128,
            unlock_time: u128,
        }

        let legacy_bytes = bincode::serialize(&LegacyMirrorV1 {
            balance: 42_000,
            zerenya_balance: 7_000,
            staked_balance: 1_000,
            reward_debt: 5,
            delegated_to: "0x1111111111111111111111111111111111111111".to_string(),
            is_contract: false,
            contract_code: vec![],
            storage: BTreeMap::new(),
            nonce: 3,
            storage_root: [9u8; 32],
            pending_unstake_amount: 500,
            unlock_time: 999,
        })
        .unwrap();

        assert!(
            bincode::deserialize::<AccountState>(&legacy_bytes).is_err(),
            "bu test eski baytların GÜNCEL şekille zaten uyumlu olmadığını varsayıyor"
        );

        let migrated = AccountState::deserialize_with_migration(&legacy_bytes)
            .expect("V1 (validator alanları olmayan) hesap kaydı okunabilmeli");

        assert_eq!(migrated.balance, 42_000);
        assert_eq!(migrated.pending_unstake_amount, 500);
        assert_eq!(migrated.unlock_time, 999);
        assert!(!migrated.is_registered_validator);
        assert_eq!(migrated.jailed_until, 0);
        assert_eq!(migrated.pending_stake_amount, 0);
        assert_eq!(migrated.pending_stake_activation_time, 0);
    }

    /// `validator_registered_at` eklenmeden ÖNCE (ama diğer validator
    /// alanları İLE) diske yazılmış bir kayıt hâlâ okunabilmeli, yeni alan
    /// güvenli varsayılanla (0 = "N/A", "genesis" ile karıştırılmamalı) dolmalı.
    #[test]
    fn v2_account_state_without_validator_registered_at_still_deserializes() {
        #[derive(Serialize, Deserialize)]
        struct LegacyMirrorV2 {
            balance: Balance,
            zerenya_balance: Balance,
            staked_balance: Balance,
            reward_debt: u128,
            delegated_to: Address,
            is_contract: bool,
            contract_code: Vec<u8>,
            storage: BTreeMap<U256, U256>,
            nonce: Nonce,
            storage_root: Hash,
            pending_unstake_amount: u128,
            unlock_time: u128,
            is_registered_validator: bool,
            jailed_until: u128,
            validator_commission_bps: u16,
            pending_stake_amount: u128,
            pending_stake_activation_time: u128,
        }

        let legacy_bytes = bincode::serialize(&LegacyMirrorV2 {
            balance: 42_000,
            zerenya_balance: 7_000,
            staked_balance: 1_000,
            reward_debt: 5,
            delegated_to: "0x1111111111111111111111111111111111111111".to_string(),
            is_contract: false,
            contract_code: vec![],
            storage: BTreeMap::new(),
            nonce: 3,
            storage_root: [9u8; 32],
            pending_unstake_amount: 500,
            unlock_time: 999,
            is_registered_validator: true,
            jailed_until: 0,
            validator_commission_bps: 250,
            pending_stake_amount: 10,
            pending_stake_activation_time: 1_000_000,
        })
        .unwrap();

        assert!(
            bincode::deserialize::<AccountState>(&legacy_bytes).is_err(),
            "bu test eski baytların GÜNCEL şekille zaten uyumlu olmadığını varsayıyor"
        );

        let migrated = AccountState::deserialize_with_migration(&legacy_bytes)
            .expect("V2 (validator_registered_at olmayan) hesap kaydı okunabilmeli");

        assert_eq!(migrated.balance, 42_000);
        assert!(migrated.is_registered_validator);
        // G13: validator_commission_bps SÖKÜLDÜ, göç bu alanı düşürür.
        assert_eq!(migrated.pending_stake_amount, 10);
        assert_eq!(
            migrated.validator_registered_at, 0,
            "yeni alan eski kayıtlar için 0 (N/A) olmalı"
        );
    }

    /// Çok eski (V0, unstake alanları da olmayan) bir kayıt tüm migration
    /// zincirinin (güncel -> V2 -> V1 -> V0) hâlâ ucuna kadar düşüp doğru
    /// okunabildiğini doğrular, V2 eklenmesi V1/V0 yolunu bozmamalı.
    #[test]
    fn v0_account_state_still_deserializes_through_the_full_migration_chain() {
        #[derive(Serialize, Deserialize)]
        struct LegacyMirrorV0 {
            balance: Balance,
            zerenya_balance: Balance,
            staked_balance: Balance,
            reward_debt: u128,
            delegated_to: Address,
            is_contract: bool,
            contract_code: Vec<u8>,
            storage: BTreeMap<U256, U256>,
            nonce: Nonce,
            storage_root: Hash,
        }

        let legacy_bytes = bincode::serialize(&LegacyMirrorV0 {
            balance: 7,
            zerenya_balance: 0,
            staked_balance: 0,
            reward_debt: 0,
            delegated_to: String::new(),
            is_contract: false,
            contract_code: vec![],
            storage: BTreeMap::new(),
            nonce: 0,
            storage_root: [0u8; 32],
        })
        .unwrap();

        let migrated = AccountState::deserialize_with_migration(&legacy_bytes)
            .expect("V0 hesap kaydı üç seviyeli zincirin sonunda hâlâ okunabilmeli");
        assert_eq!(migrated.balance, 7);
        assert_eq!(migrated.pending_unstake_amount, 0);
        assert!(!migrated.is_registered_validator);
    }
}

#[cfg(test)]
mod governance_tests {
    use super::*;

    /// Eski (V1) diskteki `Proposal` şeklini yeniden üreten yerel "ayna" struct;
    /// `ProposalV1`'in kendisi private olduğundan, gerçek eski disk byte'larını
    /// simüle etmek için `account_state_migration_tests`'teki AYNI teknik.
    #[derive(Serialize)]
    struct LegacyProposalV1Mirror {
        proposal_id: Hash,
        proposer: Address,
        description: Vec<u8>,
        created_at: u128,
        votes_for: u128,
        votes_against: u128,
        voters: BTreeSet<Address>,
    }

    #[test]
    fn proposal_migration_reads_legacy_v1_bytes_with_embedded_voters() {
        let mut voters = BTreeSet::new();
        voters.insert("0xaaaa000000000000000000000000000000000a".to_string());
        voters.insert("0xbbbb000000000000000000000000000000000b".to_string());
        let legacy = LegacyProposalV1Mirror {
            proposal_id: [9u8; 32],
            proposer: "0xcccc000000000000000000000000000000000c".to_string(),
            description: b"legacy".to_vec(),
            created_at: 123,
            votes_for: 10,
            votes_against: 5,
            voters: voters.clone(),
        };
        let bytes = bincode::serialize(&legacy).unwrap();

        let (migrated, legacy_voters) =
            Proposal::deserialize_detecting_legacy(&bytes).expect("V1 bytes must still parse");
        assert_eq!(migrated.votes_for, 10);
        assert_eq!(migrated.votes_against, 5);
        assert_eq!(legacy_voters, Some(voters));
    }

    /// G13: V4 (komisyon+delegasyon alanlı) disk kaydı güncel şekle göçerken
    /// iki alan sessizce DÜŞER, kalan her şey birebir korunur.
    #[test]
    fn g13_v4_account_bytes_migrate_dropping_commission_and_delegation() {
        let v4 = AccountStateV4 {
            delegated_to: "0x9999999999999999999999999999999999999999".to_string(),
            validator_commission_bps: 250,
            balance: 42,
            staked_balance: 7,
            nonce: 3,
            is_registered_validator: true,
            ..Default::default()
        };
        let bytes = bincode::serialize(&v4).unwrap();
        let migrated = AccountState::deserialize_with_migration(&bytes).unwrap();
        assert_eq!(migrated.balance, 42);
        assert_eq!(migrated.staked_balance, 7);
        assert_eq!(migrated.nonce, 3);
        assert!(migrated.is_registered_validator);
        // sökülen alanlara erişim zaten derlenmez, göçün kalanı bozmadığı kanıt.
    }

    #[test]
    fn proposal_status_defaults_to_active_after_v1_migration() {
        let legacy = LegacyProposalV1Mirror {
            proposal_id: [1u8; 32],
            proposer: "0x1111111111111111111111111111111111111a".to_string(),
            description: Vec::new(),
            created_at: 0,
            votes_for: 0,
            votes_against: 0,
            voters: BTreeSet::new(),
        };
        let bytes = bincode::serialize(&legacy).unwrap();
        let migrated = Proposal::deserialize_with_migration(&bytes).unwrap();
        assert_eq!(migrated.status, ProposalStatus::Active);
    }

    /// Güncel-şekil kayıtların, katı (trailing-bytes-yok) deserialize'la hâlâ
    /// normal şekilde okunabildiğini doğrular, `strict_deserialize`'a geçişin
    /// gerçek (V1 olmayan) veriyi bozmadığını kanıtlar.
    #[test]
    fn proposal_migration_round_trips_current_shape_without_regression() {
        let proposal = Proposal {
            proposal_id: [2u8; 32],
            proposer: "0x2222222222222222222222222222222222222b".to_string(),
            description: b"current".to_vec(),
            created_at: 555,
            votes_for: 7,
            votes_against: 3,
            status: ProposalStatus::Succeeded,
            action: consensus::ProposalAction::Text,
            executes_at_epoch: 0,
            voting_ends_at_epoch: 0,
        };
        let bytes = bincode::serialize(&proposal).unwrap();
        let (migrated, legacy_voters) = Proposal::deserialize_detecting_legacy(&bytes).unwrap();
        assert_eq!(migrated.status, ProposalStatus::Succeeded);
        assert_eq!(migrated.votes_for, 7);
        assert!(legacy_voters.is_none());
    }

    #[test]
    fn effective_status_transitions_active_to_expired_with_zero_votes() {
        let proposal = Proposal {
            proposal_id: [3u8; 32],
            proposer: "0x0".to_string(),
            description: Vec::new(),
            created_at: 0, // ms
            votes_for: 0,
            votes_against: 0,
            status: ProposalStatus::Active,
            action: consensus::ProposalAction::Text,
            executes_at_epoch: 0,
            voting_ends_at_epoch: 0,
        };
        let voting_period = 7 * 24 * 60 * 60;
        let expiry = 30 * 24 * 60 * 60;
        assert_eq!(
            effective_status(&proposal, 100, voting_period, expiry),
            ProposalStatus::Active
        );
        assert_eq!(
            effective_status(&proposal, voting_period + 1, voting_period, expiry),
            ProposalStatus::Expired
        );
    }

    #[test]
    fn effective_status_transitions_to_succeeded_and_rejected_by_vote_tally() {
        let voting_period = 7 * 24 * 60 * 60;
        let expiry = 30 * 24 * 60 * 60;
        let base = Proposal {
            proposal_id: [4u8; 32],
            proposer: "0x0".to_string(),
            description: Vec::new(),
            created_at: 0,
            votes_for: 10,
            votes_against: 5,
            status: ProposalStatus::Active,
            action: consensus::ProposalAction::Text,
            executes_at_epoch: 0,
            voting_ends_at_epoch: 0,
        };
        assert_eq!(
            effective_status(&base, voting_period + 1, voting_period, expiry),
            ProposalStatus::Succeeded
        );

        let rejected = Proposal {
            votes_for: 5,
            votes_against: 10,
            ..base
        };
        assert_eq!(
            effective_status(&rejected, voting_period + 1, voting_period, expiry),
            ProposalStatus::Rejected
        );
    }

    #[test]
    fn effective_status_becomes_archived_after_proposal_expiry_secs() {
        let voting_period = 7 * 24 * 60 * 60;
        let expiry = 30 * 24 * 60 * 60;
        let proposal = Proposal {
            proposal_id: [5u8; 32],
            proposer: "0x0".to_string(),
            description: Vec::new(),
            created_at: 0,
            votes_for: 10,
            votes_against: 1,
            status: ProposalStatus::Active,
            action: consensus::ProposalAction::Text,
            executes_at_epoch: 0,
            voting_ends_at_epoch: 0,
        };
        // Succeeded ama henüz expiry'ye ulaşmadı.
        assert_eq!(
            effective_status(&proposal, voting_period + 1, voting_period, expiry),
            ProposalStatus::Succeeded
        );
        // expiry'ye ulaşınca (durum Succeeded olsa bile) Archived'e geçer.
        assert_eq!(
            effective_status(&proposal, expiry, voting_period, expiry),
            ProposalStatus::Archived
        );
    }
}

// BLOCK STRUCTURE

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub number: u64,
    pub timestamp: u128,
    pub parent_hash: [u8; 32],
    pub state_root: [u8; 32],
    // 📜 MANİFESTO VE EKSTRA VERİLER İÇİN YENİ ALAN
    pub extra_data: Vec<u8>,
}

// TARİHSEL ZİNCİR DEPOSU: block_/Receipt_/tx_body_ anahtarları `contract_code`a
// bincode ile; `AccountState`e alan eklenmez (state_root değişir).

/// `block_<N>` anahtarının içeriği (N≥1). Genesis'in `block_0`'ı (yukarıdaki
/// `BlockHeader`, ayrı ve kasıtlı olarak farklı bir ham-yazım yoluyla) bunun
/// KAPSAMI DIŞINDA, her zaman özel durum olarak ele alınır.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivedBlockHeader {
    pub number: u64,
    /// Kendi hash'ini içermez (`block_0` ile aynı ilke): hash her zaman saklanan
    /// ham baytların keccak256'sı olarak TÜRETİLİR, ayrıca saklanmaz.
    pub parent_hash: Hash,
    pub state_root: Hash,
    pub timestamp: u128,
    /// Bloktaki işlemlerin `tx_id`leri (`Transaction::hash()` değil): RPC'nin
    /// döndürdüğü ve `Receipt_`/`tx_body_` anahtarlarının kullandığı değer.
    pub tx_hashes: Vec<Hash>,
}

/// Tek bir EVM log'u, adres/topics/data AYRI alanlar (evm.rs'teki eski
/// düz-string-birleştirme şemasının aksine, log sınırları ve `data` kaybolmaz).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivedLog {
    pub address: Address,
    pub topics: Vec<Hash>,
    pub data: Vec<u8>,
}

/// `Receipt_<hash>` anahtarının YENİ içeriği (eski şema: ya `b"[]"`, ya
/// `FAILED_RECEIPT_MARKER`, ya da bozuk bir düz-topic-json'uydu).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivedReceipt {
    pub status: bool,
    /// Ham gas birimi, `gas_used * gas_price` DEĞİL.
    pub gas_used: u64,
    pub contract_address: Option<Address>,
    pub logs: Vec<ArchivedLog>,
    /// İşlemin yürütüldüğü blok; `blockHash`/`transactionIndex` türetmek için.
    /// `archive_transaction` yazım anındaki `__GLOBAL_BLOCK_HEIGHT__`tan doldurur.
    pub block_number: u64,
}

/// Operatör paneli grafikleri (`zagros_getMetricsHistory`): mempool/gas/disk
/// anlık görüntüsü (60 sn). `MetricsSample_<index % MAX_METRICS_SAMPLES>`
/// döner tampon, tek yazıcı (üretici döngüsü), atomik sayaç gerekmez.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSample {
    pub timestamp: u64,
    pub block_height: u128,
    pub mempool_load: u64,
    pub stress_multiplier: u128,
    pub disk_usage_bytes: u64,
}

pub const MAX_METRICS_SAMPLES: u128 = 200;
pub const METRICS_SAMPLE_NEXT_INDEX_KEY: &str = "__METRICS_SAMPLE_NEXT_INDEX__";

pub fn metrics_sample_key(index: u128) -> String {
    format!("MetricsSample_{}", index % MAX_METRICS_SAMPLES)
}

// VALIDATOR INFO

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ValidatorInfo {
    /// Validator address
    pub address: Address,

    /// Total staked amount (self + delegated)
    pub total_stake: Balance,

    /// Self-staked amount
    pub self_stake: Balance,

    /// Commission rate (0-100)
    pub commission_rate: u8,

    /// Is validator active?
    pub is_active: bool,

    /// Total blocks produced
    pub blocks_produced: u64,

    /// Reputation score
    pub reputation: u64,
}

// GOVERNANCE: spam korumalı, O(1) oy (ayrı `ProposalVote_<id>_<addr>` anahtarları).
// Enactment yok, `Executed` set edilmez (gelecek için ayrılmış).

/// Öneri yaşam döngüsü. `Pending`/`Executed` üretilmez (ileride enactment);
/// `effective_status` `Active`'ten başlar, pencereye göre `Succeeded`/`Rejected`/
/// `Expired`, `proposal_expiry_secs` dolunca `Archived`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ProposalStatus {
    Pending,
    #[default]
    Active,
    Succeeded,
    Rejected,
    Expired,
    Executed,
    Archived,
    /// G12: kabul edildi, timelock bekliyor, `executes_at_epoch`'ta uygulanır.
    Queued,
    /// G12: Faz A 3-of-5 multisig vetosu (yalnız consensus kanalı).
    Vetoed,
}

impl std::fmt::Display for ProposalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ProposalStatus::Pending => "Pending",
            ProposalStatus::Active => "Active",
            ProposalStatus::Succeeded => "Succeeded",
            ProposalStatus::Rejected => "Rejected",
            ProposalStatus::Expired => "Expired",
            ProposalStatus::Executed => "Executed",
            ProposalStatus::Archived => "Archived",
            ProposalStatus::Queued => "Queued",
            ProposalStatus::Vetoed => "Vetoed",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Proposal {
    pub proposal_id: Hash,
    pub proposer: Address,
    /// Free-form proposal content (or a pointer/hash to off-chain content).
    pub description: Vec<u8>,
    pub created_at: u128,
    pub votes_for: u128,
    pub votes_against: u128,
    /// Kalıcı durum (`Executed`/`Archived` buraya yazılır); `Succeeded`/`Rejected`/
    /// `Expired` `effective_status` ile her okumada tembelce hesaplanır.
    pub status: ProposalStatus,
    /// G12: tipli öneri gövdesi (Text = legacy davranış, birebir).
    pub action: consensus::ProposalAction,
    /// G12: `Queued` durumunda uygulanacağı epoch (0 = yok).
    pub executes_at_epoch: u64,
    /// G12: tipli önerilerde oylama penceresinin bittiği epoch (0 = legacy Text).
    pub voting_ends_at_epoch: u64,
    // `voters` kümesi struct'ta YOK (O(1) oylama): oylar ayrı
    // `ProposalVote_<id>_<addr>` anahtarlarında tutulur. Eski (V1) diskteki
    // kayıtlar `deserialize_with_migration` ile hâlâ okunabilir, bkz. altta.
}

/// Önerinin efektif durumu: zaman bağımlı geçişler her çağrıda taze hesaplanır. Saf fonksiyon.
pub fn effective_status(
    proposal: &Proposal,
    now_secs: u64,
    voting_period_secs: u64,
    proposal_expiry_secs: u64,
) -> ProposalStatus {
    if matches!(
        proposal.status,
        ProposalStatus::Executed
            | ProposalStatus::Archived
            | ProposalStatus::Queued
            | ProposalStatus::Vetoed
    ) {
        return proposal.status;
    }
    // 🚨 BİRİM: `created_at` SANİYE (driver `timestamp_ms / 1000` geçirir).
    // Fazladan `/ 1000` her öneriyi anında `Archived` gösterir ya da efektif
    // pencereyi 1000× uzatıp `max_active_proposals` tavanıyla governance'ı kilitler.
    let created_secs = proposal.created_at as u64;
    if now_secs >= created_secs.saturating_add(proposal_expiry_secs) {
        return ProposalStatus::Archived;
    }
    if now_secs < created_secs.saturating_add(voting_period_secs) {
        return ProposalStatus::Active;
    }
    // Oylama penceresi kapandı, henüz süresi dolmadı.
    if proposal.votes_for == 0 && proposal.votes_against == 0 {
        return ProposalStatus::Expired;
    }
    if proposal.votes_for > proposal.votes_against {
        ProposalStatus::Succeeded
    } else {
        ProposalStatus::Rejected
    }
}

/// G12 ÖNCESİ (V2) disk şekli, `action`/`executes_at_epoch` alanları yok.
/// Göç: alanlar Text/0 varsayılanıyla doldurulur (legacy davranış birebir).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProposalV2 {
    proposal_id: Hash,
    proposer: Address,
    description: Vec<u8>,
    created_at: u128,
    votes_for: u128,
    votes_against: u128,
    status: ProposalStatus,
}

impl From<ProposalV2> for Proposal {
    fn from(v2: ProposalV2) -> Self {
        Proposal {
            proposal_id: v2.proposal_id,
            proposer: v2.proposer,
            description: v2.description,
            created_at: v2.created_at,
            votes_for: v2.votes_for,
            votes_against: v2.votes_against,
            status: v2.status,
            action: consensus::ProposalAction::Text,
            executes_at_epoch: 0,
            voting_ends_at_epoch: 0,
        }
    }
}

/// `Proposal`'ın O(1)-oylama refactor'ünden ÖNCEKİ diskteki şekli (`voters`
/// gömülü, `status` yok). `AccountState`/`BridgeProposal`'daki VN göç deseniyle
/// birebir aynı, bkz. bu dosyanın başındaki `AccountState` göç yorumu.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProposalV1 {
    proposal_id: Hash,
    proposer: Address,
    description: Vec<u8>,
    created_at: u128,
    votes_for: u128,
    votes_against: u128,
    voters: BTreeSet<Address>,
}

impl From<ProposalV1> for Proposal {
    fn from(v1: ProposalV1) -> Self {
        Proposal {
            proposal_id: v1.proposal_id,
            proposer: v1.proposer,
            description: v1.description,
            created_at: v1.created_at,
            votes_for: v1.votes_for,
            votes_against: v1.votes_against,
            status: ProposalStatus::Active,
            action: consensus::ProposalAction::Text,
            executes_at_epoch: 0,
            voting_ends_at_epoch: 0,
            // `v1.voters` burada düşürülür; `Executor::load_proposal` V1'i algılayıp
            // `ProposalVote_<id>_<addr>` anahtarlarına geri doldurur.
        }
    }
}

/// Tüm baytların tüketilmesini zorunlu kılan katı deserialize; göç zincirinde
/// eski baytların "başarılı" ama yanlış eşleşmesini önler.
fn strict_deserialize<'a, T: serde::de::Deserialize<'a>>(
    bytes: &'a [u8],
) -> std::result::Result<T, bincode::Error> {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .deserialize(bytes)
}

impl Proposal {
    /// Güncel şekli mi V1 (gömülü `voters`) şeklini mi okuduğunu da döndürür;
    /// V1'de çağıran legacy oyları yeni anahtar şemasına geri doldurmalı. Yan etkisiz.
    pub fn deserialize_detecting_legacy(
        bytes: &[u8],
    ) -> std::result::Result<(Self, Option<BTreeSet<Address>>), String> {
        // 🚨 Trailing bytes'a izin veren deserialize V1 kaydını yanlış "başarılı"
        // ayrıştırıp aynı adresin ikinci oyuna yol açardı; `strict_deserialize` şart.
        if let Ok(p) = strict_deserialize::<Proposal>(bytes) {
            return Ok((p, None));
        }
        // G12 (V3) öncesi kayıtlar: action/executes_at_epoch alanları yok.
        if let Ok(v2) = strict_deserialize::<ProposalV2>(bytes) {
            return Ok((Proposal::from(v2), None));
        }
        match strict_deserialize::<ProposalV1>(bytes) {
            Ok(v1) => {
                let voters = v1.voters.clone();
                Ok((Proposal::from(v1), Some(voters)))
            }
            Err(e) => Err(format!(
                "Proposal deserialize edilemedi (güncel VE V1 şekli denendi): {}",
                e
            )),
        }
    }

    /// Göç farkında deserialize; V1 gömülü `voters`ı düşürür. Legacy oyları
    /// korumak isteyen `deserialize_detecting_legacy` kullanmalı.
    pub fn deserialize_with_migration(bytes: &[u8]) -> std::result::Result<Self, String> {
        Self::deserialize_detecting_legacy(bytes).map(|(p, _)| p)
    }
}

/// Şeması değişen kritik yapıların tek seferlik göçünün hangi sürümle/ne zaman
/// tamamlandığını kaydeden ortak şekil (R8); kalıcı sentinel anahtar altında saklanır.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationRecord {
    pub version: u32,
    pub completed_at_unix_secs: u64,
}

// KÖPRÜ YAKMA GÖRÜNÜRLÜK İNDEKSİ: genel event-log RPC'si yok, haberci çekimleri
// buradan izler; dar, amaca özel indeks.

/// Sınırlı, yalnız ekleme köprü yakma indeksinin bir girdisi
/// (`Executor::record_bridge_burn`). `index` tekdüze artan imleç; indeks
/// budansa da (en eski girdiler düşer) geçerli kalır.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeBurnRecord {
    pub index: u128,
    pub tx_id: Hash,
    pub sender: Address,
    pub amount: u128,
    pub timestamp: u128,
}

/// "Gelen transfer" görünürlük indeksinin bir girdisi (`Executor::record_transfer`),
/// `BridgeBurnRecord` deseni: dApp `zagros_getReceivedTransfers` ile artımlı
/// tarar. `Receipt_<tx_id>` kalıcı kayıt, bu yalnız tarama imleci. `asset` "ZAGROS"/"ZERENYA".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRecord {
    pub index: u128,
    pub tx_id: Hash,
    pub sender: Address,
    pub receiver: Address,
    pub amount: u128,
    pub asset: String,
    pub timestamp: u128,
}

// ERROR TYPES

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZagrosError {
    /// Insufficient balance
    InsufficientBalance,

    /// Invalid signature
    InvalidSignature,

    /// Invalid nonce
    InvalidNonce,

    /// Transaction expired
    TransactionExpired,

    /// Gas limit exceeded
    GasLimitExceeded,

    /// Contract execution failed
    ContractExecutionFailed,

    /// Account not found
    AccountNotFound,

    /// Mempool full
    MempoolFull,

    /// Invalid address
    InvalidAddress,

    /// Staking error
    StakingError(String),

    /// Bridge error
    BridgeError(String),

    /// Reentrancy attack detected
    Reentrancy,

    /// Database error
    DatabaseError(String),

    /// P2P networking error
    P2pError(String),

    /// Configuration error
    ConfigError(String),

    /// Gönderen, işlem değeri ve gas ücretini birlikte karşılayacak yeterli bakiyeye sahip değil
    InsufficientBalanceForGas,

    /// Generic error
    Other(String),
}

impl fmt::Display for ZagrosError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZagrosError::InsufficientBalance => write!(f, "Insufficient balance"),
            ZagrosError::InvalidSignature => write!(f, "Invalid signature"),
            ZagrosError::InvalidNonce => write!(f, "Invalid nonce"),
            ZagrosError::TransactionExpired => write!(f, "Transaction expired"),
            ZagrosError::GasLimitExceeded => write!(f, "Gas limit exceeded"),
            ZagrosError::ContractExecutionFailed => write!(f, "Contract execution failed"),
            ZagrosError::AccountNotFound => write!(f, "Account not found"),
            ZagrosError::MempoolFull => write!(f, "Mempool is full"),
            ZagrosError::InvalidAddress => write!(f, "Invalid address"),
            ZagrosError::StakingError(msg) => write!(f, "Staking error: {}", msg),
            ZagrosError::BridgeError(msg) => write!(f, "Bridge error: {}", msg),
            ZagrosError::Reentrancy => write!(
                f,
                "Reentrancy attack detected - address already being processed"
            ),
            ZagrosError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            ZagrosError::P2pError(msg) => write!(f, "P2P error: {}", msg),
            ZagrosError::ConfigError(msg) => write!(f, "Config error: {}", msg),
            ZagrosError::InsufficientBalanceForGas => write!(
                f,
                "Gas ücreti için bakiye yetersiz: değer + gas miktarını karşılayacak ZAGROS yok"
            ),
            ZagrosError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ZagrosError {}

// Implement From<ConfigError> for ZagrosError
impl From<crate::config::ConfigError> for ZagrosError {
    fn from(err: crate::config::ConfigError) -> Self {
        ZagrosError::ConfigError(err.to_string())
    }
}

impl From<ZagrosError> for zagros_primitives::ZagrosError {
    fn from(err: ZagrosError) -> Self {
        match err {
            ZagrosError::InsufficientBalance => zagros_primitives::ZagrosError::InsufficientBalance,
            ZagrosError::InvalidSignature => zagros_primitives::ZagrosError::InvalidSignature,
            ZagrosError::InvalidNonce => zagros_primitives::ZagrosError::InvalidNonce,
            ZagrosError::TransactionExpired => zagros_primitives::ZagrosError::TransactionExpired,
            ZagrosError::GasLimitExceeded => zagros_primitives::ZagrosError::GasLimitExceeded,
            ZagrosError::ContractExecutionFailed => {
                zagros_primitives::ZagrosError::ContractExecutionFailed
            }
            ZagrosError::AccountNotFound => zagros_primitives::ZagrosError::AccountNotFound,
            ZagrosError::MempoolFull => zagros_primitives::ZagrosError::MempoolFull,
            ZagrosError::InvalidAddress => zagros_primitives::ZagrosError::InvalidAddress,
            ZagrosError::StakingError(msg) => zagros_primitives::ZagrosError::StakingError(msg),
            ZagrosError::BridgeError(msg) => zagros_primitives::ZagrosError::BridgeError(msg),
            ZagrosError::Reentrancy => zagros_primitives::ZagrosError::Reentrancy,
            ZagrosError::DatabaseError(msg) => zagros_primitives::ZagrosError::DatabaseError(msg),
            ZagrosError::P2pError(msg) => zagros_primitives::ZagrosError::P2pError(msg),
            ZagrosError::ConfigError(msg) => zagros_primitives::ZagrosError::ConfigError(msg),
            ZagrosError::InsufficientBalanceForGas => {
                zagros_primitives::ZagrosError::InsufficientBalanceForGas
            }
            ZagrosError::Other(msg) => zagros_primitives::ZagrosError::Other(msg),
        }
    }
}

pub type Result<T> = std::result::Result<T, ZagrosError>;

#[cfg(test)]
mod evm_deploy_tests {
    use super::*;

    /// Deploy ölçütü TEK kaynaktır: `evm.rs`'in `TxKind::Create` seçimi ile
    /// executor'ın x100 üretim harcı aynı yordamı kullanır. Ölçüt kayarsa harç
    /// yanlış işlem kümesinden alınır, bu yüzden çivileniyor.
    #[test]
    fn is_evm_deploy_matches_every_empty_receiver_form() {
        assert!(is_evm_deploy(""));
        assert!(is_evm_deploy("0x"));
        assert!(is_evm_deploy("0x0000000000000000000000000000000000000000"));

        assert!(!is_evm_deploy("0x2222222222222222222222222222222222222222"));
        assert!(!is_evm_deploy("0x0000000000000000000000000000000000000001"));
    }
}

#[cfg(test)]
mod signature_tests {
    use super::*;

    /// Gerçek EIP-1559 işlemi imzalayıp `decode_and_convert_tx` ile AYNI formatta
    /// `Transaction` kurar; alan bağlaması zorunlu olduğundan sighash gerçekten o RLP'ye ait olmalı.
    fn build_bound_evm_tx(
        secret_key: &secp256k1::SecretKey,
        to: &str,
        value: u128,
        nonce: u64,
        data: Vec<u8>,
    ) -> Transaction {
        use ethers_core::types::transaction::eip2718::TypedTransaction;
        use ethers_core::types::{Address as EthAddress, Eip1559TransactionRequest, U256};

        let to_addr: EthAddress = to.parse().expect("gecerli adres");
        let req = Eip1559TransactionRequest::new()
            .to(to_addr)
            .value(U256::from(value))
            .nonce(U256::from(nonce))
            .gas(U256::from(100_000u64))
            .max_fee_per_gas(U256::from(1_000_000_000u64))
            .max_priority_fee_per_gas(U256::from(1u64))
            .chain_id(CHAIN_ID)
            .data(data.clone());
        let typed: TypedTransaction = req.into();
        let sighash = typed.sighash();

        // secp256k1 ile sighash üzerinde imzala (EIP-1559'da v = parite).
        let secp = secp256k1::Secp256k1::new();
        let msg = secp256k1::Message::from_digest_slice(sighash.as_bytes()).unwrap();
        let rec_sig = secp.sign_ecdsa_recoverable(&msg, secret_key);
        let (rec_id, compact) = rec_sig.serialize_compact();
        let eth_sig = ethers_core::types::Signature {
            r: U256::from_big_endian(&compact[0..32]),
            s: U256::from_big_endian(&compact[32..64]),
            v: rec_id.to_i32() as u64,
        };
        let raw_rlp = typed.rlp_signed(&eth_sig).to_vec();

        let mut signature = Vec::with_capacity(66 + raw_rlp.len());
        signature.extend_from_slice(&compact);
        signature.push(rec_id.to_i32() as u8);
        signature.push(2u8); // eth_type = Eip1559
                             // sighash TASINMAZ, ham RLP'den turetilir (bkz. verify_signature_production)
        signature.extend_from_slice(&raw_rlp);

        let receiver = to.to_ascii_lowercase();
        let (tx_type, amount, payload) = derive_native_call(&receiver, &data, value, false);
        Transaction {
            tx_id: [0u8; 32],
            tx_type,
            sender: Transaction::address_from_secret_key(secret_key),
            amount,
            receiver,
            payload,
            signature,
            timestamp: 1_000,
            nonce,
            gas_limit: 100_000,
            gas_price: 1,
            chain_id: CHAIN_ID,
        }
    }

    fn base_tx() -> Transaction {
        Transaction {
            tx_id: [0u8; 32],
            tx_type: TxType::Transfer,
            sender: String::new(),
            amount: 10,
            receiver: "0x2222222222222222222222222222222222222222".to_string(),
            payload: Vec::new(),
            signature: Vec::new(),
            timestamp: 1_000,
            nonce: 0,
            gas_limit: 21_000,
            gas_price: 1,
            chain_id: CHAIN_ID,
        }
    }

    #[test]
    fn properly_signed_transaction_is_accepted() {
        let secret_key = secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let mut tx = base_tx();
        tx.sender = Transaction::address_from_secret_key(&secret_key);
        tx.sign(&secret_key);

        assert!(tx.verify_signature());
        assert!(tx.validate().is_ok());
    }

    #[test]
    fn zero_amount_transfer_is_rejected() {
        // 🛡️ [20]: amount==0 Transfer (ve Swap/Stake türleri) fail-closed reddedilir.
        let secret_key = secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let mut tx = base_tx();
        tx.amount = 0;
        tx.sender = Transaction::address_from_secret_key(&secret_key);
        tx.sign(&secret_key);

        // İmza geçerli olsa da amount==0 reddedilmeli.
        assert!(tx.verify_signature());
        assert!(
            tx.validate().is_err(),
            "zero-amount transfer must be rejected"
        );
    }

    #[test]
    fn zero_amount_swapsell_is_rejected() {
        let secret_key = secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let mut tx = base_tx();
        tx.tx_type = TxType::SwapSell;
        tx.amount = 0;
        tx.sender = Transaction::address_from_secret_key(&secret_key);
        tx.sign(&secret_key);
        assert!(
            tx.validate().is_err(),
            "zero-amount SwapSell must be rejected"
        );
    }

    #[test]
    fn zero_amount_unstake_zagros_is_accepted_it_means_claim_matured_withdrawal() {
        // 🚨 Regresyon: `UnstakeZagros` için `amount == 0` no-op değil, "kilidi
        // dolmuş bekleyen çekimi aktar" isteği (dApp amount=0 gönderir).
        let secret_key = secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let mut tx = base_tx();
        tx.tx_type = TxType::UnstakeZagros;
        tx.amount = 0;
        tx.sender = Transaction::address_from_secret_key(&secret_key);
        tx.sign(&secret_key);
        assert!(
            tx.validate().is_ok(),
            "amount=0 UnstakeZagros 'bekleyen çekimi talep et' anlamına gelir, reddedilmemeli"
        );
    }

    #[test]
    fn unsigned_transaction_is_rejected() {
        let mut tx = base_tx();
        tx.sender = "0x1111111111111111111111111111111111111111".to_string();
        // No .sign() call: signature stays empty, exactly what an attacker who
        // doesn't own the sender's private key would submit.
        assert!(!tx.verify_signature());
        assert!(matches!(tx.validate(), Err(ZagrosError::InvalidSignature)));
    }

    /// 97 baytlık (r||s||v||external_hash) formatı taklit eder; `external_hash`
    /// cüzdanın imzaladığı keyfi hash.
    fn sign_evm_style(secret_key: &secp256k1::SecretKey, external_hash: &[u8; 32]) -> Vec<u8> {
        use secp256k1::{Message, Secp256k1};

        let secp = Secp256k1::new();
        let message = Message::from_digest_slice(external_hash).unwrap();
        let recoverable_sig = secp.sign_ecdsa_recoverable(&message, secret_key);
        let (recovery_id, compact) = recoverable_sig.serialize_compact();

        let mut signature = Vec::with_capacity(97);
        signature.extend_from_slice(&compact);
        signature.push(recovery_id.to_i32() as u8);
        signature.extend_from_slice(external_hash);
        signature
    }

    /// 🚨 EVM alanları imzaya bağlı olmalı (`receiver` değişmiş işlem RET);
    /// eski sighash taşıyan format da reddedilir.
    #[test]
    fn the_old_signature_layout_that_carried_a_sighash_no_longer_verifies() {
        let key = secp256k1::SecretKey::from_slice(&[11u8; 32]).unwrap();
        let mut tx = build_bound_evm_tx(
            &key,
            "0x3333333333333333333333333333333333333333",
            10u128.pow(15),
            3,
            Vec::new(),
        );
        assert!(tx.verify_signature(), "yeni format gecerli olmali");

        // ESKI duzeni yeniden kur: r||s||v(65) || eth_type(1) || sighash(32) || RLP
        let raw_rlp = tx.signature[66..].to_vec();
        let sighash = evm_sighash_from_raw_rlp(&raw_rlp).expect("RLP cozulebilmeli");
        let mut legacy = tx.signature[0..66].to_vec();
        legacy.extend_from_slice(&sighash);
        legacy.extend_from_slice(&raw_rlp);
        tx.signature = legacy;

        assert!(
            !tx.verify_signature(),
            "sighash TASIYAN eski duzen REDDEDILMELI - aksi halde iki format bir arada \
             kabul edilir ve hangi baytlarin imzaya bagli oldugu belirsizlesir"
        );
    }

    /// 🚨 Boyut regresyonu: işlem boyutu blok kapasitesini doğrudan belirler
    /// (256 KB ÷ boyut); alan eklemek ya da imzaya bir şey gömmek burada yakalanır.
    #[test]
    fn a_bound_evm_transaction_stays_within_its_measured_byte_budget() {
        let _guard = WireRuleset::set(2);
        let tx = build_bound_evm_tx(
            &secp256k1::SecretKey::from_slice(&[9u8; 32]).unwrap(),
            "0x2222222222222222222222222222222222222222",
            10u128.pow(15),
            7,
            Vec::new(),
        );
        let size = bincode::serialized_size(&tx).unwrap();
        // Ölçüldü: 439 → 407 → **290** bayt (sıkıştırılmış tel formatı);
        // 256 KB blok: 597 → 644 → **903** işlem.
        assert!(
            size <= 295,
            "islem boyutu {size} bayt - butce 295. Buyume, 256 KB'lik bloga giren \
             islem sayisini dogrudan dusurur (blok basina ~{} islem)",
            262_144 / size.max(1)
        );
        // Alt sinir da anlamli: bu kadar kucukse muhtemelen bir alan KAYBOLMUS.
        assert!(
            size > 250,
            "islem beklenmedik sekilde kucuk ({size}) - alan kaybi olabilir"
        );
    }

    /// Tel formatı bayrağı SÜREÇ-GLOBAL olduğu için, onu değiştiren testler
    /// paralel koşarken birbirini bozabilir. Bu koruyucu hem kilitler hem de
    /// test bitince varsayılana (1 = eski format) geri döner.
    static WIRE_FLAG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct WireRuleset(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);

    impl WireRuleset {
        fn set(value: u32) -> Self {
            let guard = WIRE_FLAG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            crate::set_tx_wire_ruleset(value);
            WireRuleset(guard)
        }
    }

    impl Drop for WireRuleset {
        fn drop(&mut self) {
            crate::set_tx_wire_ruleset(1);
        }
    }

    /// Varsayılan eski format: yeni binary aktivasyona kadar eski düzeni yazar
    /// (önce hepsi geçer, sonra epoch sınırında birlikte çevrilir).
    #[test]
    fn legacy_layout_is_the_default_until_the_upgrade_activates() {
        let _guard = WireRuleset::set(1);
        let tx = build_bound_evm_tx(
            &secp256k1::SecretKey::from_slice(&[31u8; 32]).unwrap(),
            "0x9999999999999999999999999999999999999999",
            10u128.pow(15),
            7,
            Vec::new(),
        );
        let size = bincode::serialized_size(&tx).unwrap();
        assert!(
            (400..=410).contains(&size),
            "yukseltme oncesi duzen 407 bayt olmali, olculen {size}"
        );
        let back: Transaction = bincode::deserialize(&bincode::serialize(&tx).unwrap()).unwrap();
        assert_eq!(back.tx_id, tx.tx_id);
        assert_eq!(back.sender, tx.sender);
    }

    /// 🚨 YÜKSELTME SENARYOSU: aktivasyondan ÖNCE yazılmış arşiv kaydı,
    /// aktivasyondan SONRA da okunabilmeli, yoksa yükseltme, geçmiş
    /// işlemlerin dekont/gövde sorgularını karartır.
    #[test]
    fn stored_records_written_before_activation_stay_readable_after_it() {
        let tx = {
            let _guard = WireRuleset::set(1);
            let tx = build_bound_evm_tx(
                &secp256k1::SecretKey::from_slice(&[32u8; 32]).unwrap(),
                "0xaaaa000000000000000000000000000000000001",
                777,
                3,
                vec![9, 9],
            );
            let old_record = tx.to_stored_bytes().unwrap();
            assert!(
                !old_record.starts_with(&TX_STORED_COMPACT_MAGIC),
                "ruleset 1'de eski duzen yazilmali"
            );
            (tx, old_record)
        };
        let (tx, old_record) = tx;

        let _guard = WireRuleset::set(2);
        let read_back = Transaction::from_stored_bytes(&old_record).unwrap();
        assert_eq!(
            read_back.tx_id, tx.tx_id,
            "eski kayit yeni ruleset'te de okunmali"
        );
        assert_eq!(read_back.sender, tx.sender);

        // Aktivasyondan sonra yazilan kayit sihirli onekli ve yine okunabilir.
        let new_record = tx.to_stored_bytes().unwrap();
        assert!(new_record.starts_with(&TX_STORED_COMPACT_MAGIC));
        assert!(
            new_record.len() < old_record.len(),
            "yeni kayit daha kucuk olmali"
        );
        assert_eq!(
            Transaction::from_stored_bytes(&new_record).unwrap().tx_id,
            tx.tx_id
        );
    }

    /// Tel formatı KAYIPSIZ olmalı: bincode üzerinden gidip gelen işlem, tüm
    /// alanlarıyla (özellikle taşınmayan `tx_id` ile) birebir aynı dönmeli.
    #[test]
    fn compact_wire_round_trips_a_bound_evm_transaction_without_losing_the_tx_id() {
        let _guard = WireRuleset::set(2);
        let tx = build_bound_evm_tx(
            &secp256k1::SecretKey::from_slice(&[21u8; 32]).unwrap(),
            "0x4444444444444444444444444444444444444444",
            10u128.pow(16),
            42,
            vec![1, 2, 3, 4],
        );
        let bytes = bincode::serialize(&tx).unwrap();
        let back: Transaction = bincode::deserialize(&bytes).unwrap();

        assert_eq!(
            back.tx_id, tx.tx_id,
            "EVM tx_id (Ethereum hash'i) korunmali"
        );
        assert_eq!(back.sender, tx.sender);
        assert_eq!(back.receiver, tx.receiver);
        assert_eq!(back.amount, tx.amount);
        assert_eq!(back.payload, tx.payload);
        assert_eq!(back.signature, tx.signature);
        assert_eq!(back.timestamp, tx.timestamp);
        assert_eq!(back.nonce, tx.nonce);
        assert_eq!(back.gas_limit, tx.gas_limit);
        assert_eq!(back.gas_price, tx.gas_price);
        assert_eq!(back.chain_id, tx.chain_id);
        assert!(back.verify_signature(), "cozulen islem hala dogrulanmali");
    }

    /// 🚨 `tx_id` HER ZAMAN türetilebilir DEĞİL: köprü yollarında öneri
    /// kimliği (`mint_proposal_id`, `burn_tx_id`) taşınır. Bu değerler aynen
    /// korunmalı, yoksa köprü bağı kopar.
    #[test]
    fn compact_wire_preserves_an_explicit_non_derivable_tx_id() {
        let _guard = WireRuleset::set(2);
        let mut tx = build_bound_evm_tx(
            &secp256k1::SecretKey::from_slice(&[22u8; 32]).unwrap(),
            "0x5555555555555555555555555555555555555555",
            5_000,
            1,
            Vec::new(),
        );
        tx.tx_id = [77u8; 32]; // ne EVM RLP hash'i ne de hash() - acikca tasinmali

        let back: Transaction = bincode::deserialize(&bincode::serialize(&tx).unwrap()).unwrap();
        assert_eq!(back.tx_id, [77u8; 32]);
    }

    /// EIP-55 sağlama toplamlı (karışık harfli) adres 20 ham bayta indirgenirse
    /// dizginin kendisi değişir; `hash()` ve state anahtarları buna bağlı
    /// olduğu için dizgi dalına düşüp AYNEN korunmalı.
    #[test]
    fn compact_wire_keeps_a_mixed_case_address_byte_for_byte() {
        let _guard = WireRuleset::set(2);
        let mut tx = build_bound_evm_tx(
            &secp256k1::SecretKey::from_slice(&[23u8; 32]).unwrap(),
            "0x6666666666666666666666666666666666666666",
            1,
            0,
            Vec::new(),
        );
        tx.receiver = "0xAbC0000000000000000000000000000000000001".to_string();
        tx.tx_id = tx.hash();

        let back: Transaction = bincode::deserialize(&bincode::serialize(&tx).unwrap()).unwrap();
        assert_eq!(back.receiver, "0xAbC0000000000000000000000000000000000001");
        assert_eq!(back.tx_id, tx.tx_id);
    }

    /// KANONİKLİK: aynı işlemin iki farklı geçerli kodlaması olmamalı, yoksa
    /// blok gövdesi baytları oynatılabilir. Üç kaçak yol da kapalı olmalı.
    #[test]
    fn compact_wire_rejects_non_canonical_encodings() {
        let tx = build_bound_evm_tx(
            &secp256k1::SecretKey::from_slice(&[24u8; 32]).unwrap(),
            "0x7777777777777777777777777777777777777777",
            9,
            0,
            Vec::new(),
        );
        let good = tx.encode_wire();
        assert!(Transaction::decode_wire(&good).is_ok());

        // (a) sonuna artik bayt
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(
            Transaction::decode_wire(&trailing).is_err(),
            "artik bayt reddedilmeli"
        );

        // (b) turetilebilir tx_id acikca yazilmis
        let mut explicit = good[..good.len() - 1].to_vec();
        explicit.push(2);
        explicit.extend_from_slice(&tx.tx_id);
        assert!(
            Transaction::decode_wire(&explicit).is_err(),
            "turetilebilir tx_id acikca yazilmamali"
        );

        // (c) 20 baytlik adres dizgi dalinda yazilmis
        let mut as_string = Vec::new();
        as_string.push(1u8);
        as_string.extend_from_slice(tx.sender.as_bytes());
        let mut smuggled = Vec::new();
        smuggled.extend_from_slice(&good[..2]); // surum + tx_type
        smuggled.push(1u8);
        put_uvarint(&mut smuggled, tx.sender.len() as u128);
        smuggled.extend_from_slice(tx.sender.as_bytes());
        smuggled.extend_from_slice(&good[2 + 21..]);
        assert!(
            Transaction::decode_wire(&smuggled).is_err(),
            "kanonik adres dizgi olarak yazilmamali"
        );
    }

    /// Non-minimal varint (gereksiz devam baytı) da ikinci bir kodlama yolu
    /// açardı, reddedilmeli.
    #[test]
    fn compact_wire_rejects_a_non_minimal_varint() {
        let mut minimal: Vec<u8> = Vec::new();
        put_uvarint(&mut minimal, 1);
        assert_eq!(minimal, vec![1]);

        let padded: &[u8] = &[0x81, 0x00];
        let mut input = padded;
        assert!(
            get_uvarint(&mut input).is_err(),
            "0x81 0x00 = 1'in ikinci yazimi, reddedilmeli"
        );
    }

    /// JSON tarafı DEĞİŞMEMELİ: sıkıştırma yalnız ikili formatta.
    #[test]
    fn json_representation_is_unchanged_by_the_compact_wire_format() {
        let tx = build_bound_evm_tx(
            &secp256k1::SecretKey::from_slice(&[25u8; 32]).unwrap(),
            "0x8888888888888888888888888888888888888888",
            123,
            5,
            Vec::new(),
        );
        let value: serde_json::Value = serde_json::to_value(&tx).unwrap();
        assert_eq!(
            value["sender"],
            serde_json::Value::String(tx.sender.clone())
        );
        assert_eq!(value["nonce"], serde_json::json!(5));
        assert!(
            value["tx_id"].is_array(),
            "tx_id JSON'da alan olarak kalmali"
        );

        let back: Transaction = serde_json::from_value(value).unwrap();
        assert_eq!(back.tx_id, tx.tx_id);
        assert_eq!(back.sender, tx.sender);
    }

    #[test]
    fn evm_origin_transaction_fields_are_bound_to_the_signature() {
        let secret_key = secp256k1::SecretKey::from_slice(&[13u8; 32]).unwrap();
        let tx = build_bound_evm_tx(
            &secret_key,
            "0x1111111111111111111111111111111111111111",
            1_000,
            0,
            Vec::new(),
        );
        assert!(tx.verify_signature(), "orijinal tx geçerli olmalı");

        // SALDIRI 1: alıcıyı değiştir (fon hırsızlığı).
        let mut stolen = tx.clone();
        stolen.receiver = "0x9999999999999999999999999999999999999999".to_string();
        assert!(
            !stolen.verify_signature(),
            "alıcısı değiştirilmiş tx REDDEDİLMELİ"
        );

        // SALDIRI 2: tutarı şişir.
        let mut inflated = tx.clone();
        inflated.amount = 999_999;
        assert!(
            !inflated.verify_signature(),
            "tutarı değiştirilmiş tx REDDEDİLMELİ"
        );

        // SALDIRI 3: nonce değiştir.
        let mut renonced = tx.clone();
        renonced.nonce = 42;
        assert!(
            !renonced.verify_signature(),
            "nonce'u değiştirilmiş tx REDDEDİLMELİ"
        );

        // SALDIRI 4: payload enjekte et.
        let mut payloaded = tx.clone();
        payloaded.payload = vec![1, 2, 3];
        assert!(
            !payloaded.verify_signature(),
            "payload'ı değiştirilmiş tx REDDEDİLMELİ"
        );
    }

    /// Ham RLP taşımayan ESKİ EVM imza formatı (97/98 bayt) artık
    /// reddedilmeli: alanların imzaya bağlı olduğu kanıtlanamaz.
    #[test]
    fn evm_origin_signature_without_raw_rlp_binding_is_rejected() {
        let secret_key = secp256k1::SecretKey::from_slice(&[9u8; 32]).unwrap();
        let mut tx = base_tx();
        tx.sender = Transaction::address_from_secret_key(&secret_key);
        let foreign_hash = [42u8; 32];
        tx.signature = sign_evm_style(&secret_key, &foreign_hash);
        assert_eq!(tx.signature.len(), 97);
        assert!(
            !tx.verify_signature(),
            "bağlamasız (97 bayt) EVM imzası REDDEDİLMELİ"
        );
    }

    /// zagros-rpc'nin GÜNCEL `decode_and_convert_tx`'inin ürettiği 98 baytlık
    /// (r||s||v||eth_type||external_hash) tip-farkında formatı taklit eder,
    /// bkz. `sign_evm_style`'ın doc yorumu (eski 97-bayt format).
    fn sign_evm_style_with_type(
        secret_key: &secp256k1::SecretKey,
        external_hash: &[u8; 32],
        eth_type: u8,
    ) -> Vec<u8> {
        use secp256k1::{Message, Secp256k1};

        let secp = Secp256k1::new();
        let message = Message::from_digest_slice(external_hash).unwrap();
        let recoverable_sig = secp.sign_ecdsa_recoverable(&message, secret_key);
        let (recovery_id, compact) = recoverable_sig.serialize_compact();

        let mut signature = Vec::with_capacity(98);
        signature.extend_from_slice(&compact);
        signature.push(recovery_id.to_i32() as u8);
        signature.push(eth_type);
        signature.extend_from_slice(external_hash);
        signature
    }

    /// 🚨 İmza doğrulaması tip baytının değerinden bağımsız olmalı (tip yalnız
    /// RPC `v`/`type` bilgisi).
    #[test]
    fn bound_evm_signature_verifies_regardless_of_the_carried_type_byte() {
        let secret_key = secp256k1::SecretKey::from_slice(&[11u8; 32]).unwrap();
        let tx = build_bound_evm_tx(
            &secret_key,
            "0x2222222222222222222222222222222222222222",
            5,
            0,
            Vec::new(),
        );
        assert!(tx.verify_signature());
        for eth_type in [0u8, 1u8, 2u8] {
            let mut variant = tx.clone();
            variant.signature[65] = eth_type;
            assert!(
                variant.verify_signature(),
                "tip baytı {eth_type} imza doğrulamasını etkilememeli"
            );
        }
    }

    #[test]
    fn evm_origin_signature_from_a_different_key_than_the_claimed_sender_is_rejected() {
        let signer_key = secp256k1::SecretKey::from_slice(&[9u8; 32]).unwrap();
        let mut tx = base_tx();
        tx.sender = "0x1111111111111111111111111111111111111111".to_string();
        tx.signature = sign_evm_style(&signer_key, &[42u8; 32]);

        assert!(!tx.verify_signature());
        assert!(matches!(tx.validate(), Err(ZagrosError::InvalidSignature)));
    }

    #[test]
    fn signature_from_a_different_key_than_the_claimed_sender_is_rejected() {
        let signer_key = secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let mut tx = base_tx();
        // Claim to be someone else's address while signing with our own key.
        tx.sender = "0x1111111111111111111111111111111111111111".to_string();
        tx.sign(&signer_key);

        assert!(!tx.verify_signature());
    }

    fn sign_hash(secret_key: &secp256k1::SecretKey, hash: &[u8; 32]) -> Signature {
        use secp256k1::{Message, Secp256k1};
        let secp = Secp256k1::new();
        let message = Message::from_digest_slice(hash).unwrap();
        let recoverable_sig = secp.sign_ecdsa_recoverable(&message, secret_key);
        let (recovery_id, compact) = recoverable_sig.serialize_compact();
        let mut signature = Vec::with_capacity(65);
        signature.extend_from_slice(&compact);
        signature.push(recovery_id.to_i32() as u8);
        signature
    }

    /// 🛡️ FAZ4.2: secp256k1 grup mertebesi `n` (big-endian). Low-S malleability
    /// testinde `n - s` (high-S ikizi) üretmek için kullanılır.
    const SECP256K1_N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];

    /// big-endian 32-baytlık `n - s` (s < n varsayılır).
    fn negate_s_mod_n(s: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let diff = SECP256K1_N[i] as i16 - s[i] as i16 - borrow;
            if diff < 0 {
                out[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                out[i] = diff as u8;
                borrow = 0;
            }
        }
        out
    }

    /// 🛡️ FAZ4.2: high-S (non-kanonik) ECDSA imzaları `recover_signer_address`
    /// tarafından reddedilmeli. Aksi halde (r, s, v) ve (r, n−s, v⊕1) aynı adrese
    /// çözülüp farklı tx_id üretir → imza malleability / dedup atlatma.
    #[test]
    fn recover_signer_address_rejects_high_s_signature() {
        let key = secp256k1::SecretKey::from_slice(&[5u8; 32]).unwrap();
        let hash = [0x42u8; 32];
        // Kanonik (low-S) imza, bu geçerli olmalı.
        let low_s = sign_hash(&key, &hash);
        assert!(
            recover_signer_address(&hash, &low_s).is_some(),
            "canonical low-S signature must still recover"
        );

        // s → n − s ile high-S ikizini kur; v paritesini de çevir (aynı adrese
        // çözülürdü) ama Low-S kontrolü recovery'den ÖNCE reddetmeli.
        let mut high_s = low_s.clone();
        let s: [u8; 32] = high_s[32..64].try_into().unwrap();
        let neg = negate_s_mod_n(&s);
        high_s[32..64].copy_from_slice(&neg);
        high_s[64] ^= 1;

        assert!(
            recover_signer_address(&hash, &high_s).is_none(),
            "high-S (malleable) signature must be rejected"
        );
    }

    // Doğrulanmış işlem chain id zorunluluğu, regresyon testleri.

    /// Merkezi kurucu RPC ön kontrolüne güvenmeden tek başına chain_id
    /// uyuşmazlığını reddetmeli (savunma derinliği kanıtı).
    #[test]
    fn from_verified_eip155_independently_rejects_a_foreign_chain_id() {
        let result = Transaction::from_verified_eip155(
            [1u8; 32],
            TxType::Transfer,
            "0x2222222222222222222222222222222222222222".to_string(),
            "0x3333333333333333333333333333333333333333".to_string(),
            0,
            Vec::new(),
            vec![0u8; 65],
            0,
            0,
            21_000,
            1,
            1, // Ethereum mainnet - CHAIN_ID (21072026) DEĞİL.
        );
        assert!(
            result.is_err(),
            "yabancı bir chain_id için imzalanmış işlem BAĞIMSIZ olarak reddedilmeli"
        );
        assert!(result.unwrap_err().to_string().contains("chain_id"));
    }

    /// Doğru chain_id ile üretilen `Transaction.chain_id` hep `CHAIN_ID` sabitine eşit.
    #[test]
    fn from_verified_eip155_accepts_the_correct_chain_id_and_stamps_the_constant() {
        let tx = Transaction::from_verified_eip155(
            [1u8; 32],
            TxType::Transfer,
            "0x2222222222222222222222222222222222222222".to_string(),
            "0x3333333333333333333333333333333333333333".to_string(),
            0,
            Vec::new(),
            vec![0u8; 65],
            0,
            0,
            21_000,
            1,
            CHAIN_ID,
        )
        .expect("doğru chain_id ile kabul edilmeli");
        assert_eq!(tx.chain_id, CHAIN_ID);
    }

    /// Keyless kurucu da bağımsız savunma taşır: listede olmayan gönderen ret,
    /// Multicall3 deployer'ı kabul + `CHAIN_ID` damgası.
    #[test]
    fn from_verified_keyless_deployment_only_accepts_allowlisted_senders() {
        let build = |sender: &str| {
            Transaction::from_verified_keyless_deployment(
                [1u8; 32],
                TxType::ContractCall { data: vec![0x60] },
                sender.to_string(),
                "0x0000000000000000000000000000000000000000".to_string(),
                0,
                Vec::new(),
                vec![0u8; 65],
                0,
                0,
                1_000_000,
                1,
            )
        };
        let rejected = build("0x2222222222222222222222222222222222222222");
        assert!(rejected.is_err(), "listede olmayan gönderen reddedilmeli");
        assert!(rejected.unwrap_err().to_string().contains("keyless"));

        // Büyük/küçük harf duyarsızlık da kanıtlanır (checksum'lı yazım).
        let accepted = build("0x05f32B3cC3888453ff71B01135B34FF8e41263F2")
            .expect("Multicall3 deployer'ı kabul edilmeli");
        assert_eq!(accepted.chain_id, CHAIN_ID);
        assert!(is_keyless_deployer(
            "0x05f32b3cc3888453ff71b01135b34ff8e41263f2"
        ));
        assert!(!is_keyless_deployer(
            "0x2222222222222222222222222222222222222222"
        ));
    }

    #[test]
    fn double_sign_proof_with_matching_signatures_is_valid() {
        let key = secp256k1::SecretKey::from_slice(&[3u8; 32]).unwrap();
        let block_hash = [1u8; 32];
        let conflicting_block_hash = [2u8; 32];
        let proof = SlashingProof {
            validator: Transaction::address_from_secret_key(&key),
            block_hash,
            conflicting_block_hash,
            first_signature: sign_hash(&key, &block_hash),
            second_signature: sign_hash(&key, &conflicting_block_hash),
            epoch: 1,
            timestamp: 1,
        };

        assert!(proof.verify_double_sign());
    }

    #[test]
    fn double_sign_proof_where_second_signature_is_from_a_different_key_is_rejected() {
        let key = secp256k1::SecretKey::from_slice(&[3u8; 32]).unwrap();
        let other_key = secp256k1::SecretKey::from_slice(&[4u8; 32]).unwrap();
        let block_hash = [1u8; 32];
        let conflicting_block_hash = [2u8; 32];
        let proof = SlashingProof {
            validator: Transaction::address_from_secret_key(&key),
            block_hash,
            conflicting_block_hash,
            first_signature: sign_hash(&key, &block_hash),
            // Not signed by the accused validator's own key, not real evidence.
            second_signature: sign_hash(&other_key, &conflicting_block_hash),
            epoch: 1,
            timestamp: 1,
        };

        assert!(!proof.verify_double_sign());
    }

    #[test]
    fn double_sign_proof_with_fabricated_signatures_is_rejected() {
        // Exactly what a free-riding attacker can produce without owning any
        // validator's private key: well-formed-looking bytes, no real signature.
        let proof = SlashingProof {
            validator: "0x1111111111111111111111111111111111111111".to_string(),
            block_hash: [1u8; 32],
            conflicting_block_hash: [2u8; 32],
            first_signature: vec![0u8; 65],
            second_signature: vec![0u8; 65],
            epoch: 1,
            timestamp: 1,
        };

        assert!(!proof.verify_double_sign());
    }
}
