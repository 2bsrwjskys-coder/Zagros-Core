// Zagros Relayer yapılandırması: iki kimlik (Ed25519 + secp256k1), iki RPC ucu
// ve köprü parametreleri TOML'dan; `ZagrosConfig` stilini izler.

use ed25519_dalek::SigningKey;
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::Path;
use zagros_executor::bridge::BridgeManager;
use zagros_types::Transaction;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayerConfig {
    /// Kalıcı durum deposu dizini. 🚨 Her relayer'ın kendi dizini olmalı:
    /// RocksDB tek sürece kilitler, aynı makinede her relayer*.toml farklı yol vermeli.
    #[serde(default = "default_data_dir")]
    pub data_dir: String,

    pub identity: IdentityConfig,
    pub ethereum: EthereumConfig,
    pub zagros: ZagrosEndpointConfig,
    pub bridge: BridgeParamsConfig,

    /// item 11: idempotency kayıtlarının (`idem:eth:*`/`idem:zagros_burn:*`/
    /// `idem:unlock_submitted:*`) saklama politikası.
    #[serde(default)]
    pub idempotency: IdempotencyConfig,
}

/// Idempotency kayıtları saklama süresi; eski (tarihsiz) kayıtlar asla otomatik silinmez.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IdempotencyConfig {
    pub retention_days: u64,
}

impl Default for IdempotencyConfig {
    fn default() -> Self {
        Self { retention_days: 30 }
    }
}

/// İki zincirdeki kimlik, kasıtlı iki ayrı anahtar: Ed25519 Zagros çoklu imza
/// akışı, secp256k1 Ethereum tarafı. Aynı anahtar iki güvenlik alanını gereksiz bağlardı.
#[derive(Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    /// Ed25519 gizli anahtarı (hex, 32 bayt), BridgeManager yetkilisi olarak
    /// kayıtlı olması gereken açık anahtarı bundan türetilir.
    pub zagros_signing_key_hex: String,
    /// secp256k1 gizli anahtarı (hex, 32 bayt), Ethereum tarafındaki
    /// `isRelayer` listesinde kayıtlı olması gereken adresi bundan türetilir.
    pub ethereum_signing_key_hex: String,
}

/// item 14: `derive(Debug)` yerine elle yazılmış, iki alan da özel anahtar,
/// bir `{:?}` çağrısı ya da hata mesajı içine gömülen config dump'ı düz metin
/// anahtar SIZDIRMASIN.
impl fmt::Debug for IdentityConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityConfig")
            .field("zagros_signing_key_hex", &"<redacted>")
            .field("ethereum_signing_key_hex", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthereumConfig {
    /// `eth_subscribe` için WebSocket uç noktası (örn. "wss://...").
    pub ws_rpc_url: String,
    /// ZagrosBridgeGateway.sol'un dağıtıldığı adres.
    pub gateway_contract_address: String,
    /// Bir `TokensLocked` olayının işleme alınmadan önce beklenecek blok
    /// onayı sayısı (reorg güvenliği, Zagros'ta bu kavram yok, tek-düğüm/
    /// anlık kesinlik).
    #[serde(default = "default_confirmation_depth")]
    pub confirmation_depth: u64,

    /// 🚨 Olay taramasının BAŞLAYACAĞI blok, kasanın deploy edildiği blok.
    /// 0 bırakılırsa relayer tüm Ethereum tarihini taramaya çalışır; sağlayıcılar
    /// bunu reddeder (Alchemy ücretsiz plan: 10 blok) ve HİÇBİR mevduat görülmez.
    #[serde(default)]
    pub start_block: u64,

    /// Tek bir `eth_getLogs` çağrısının kapsayacağı azami blok sayısı.
    /// Sağlayıcı limitine göre ayarlanır (Alchemy ücretsiz: 10, ücretli/publicnode
    /// çok daha yüksek). Yetişme birden çok turda parça parça yapılır.
    #[serde(default = "default_max_log_range")]
    pub max_log_range: u64,
    /// Kilit açmada kullanılacak ERC20 (PAXG). Bilinen sınır: burn calldata'sı
    /// orijinal token'ı taşımaz, tek sabit token desteklenir.
    pub unlock_token_address: String,

    /// Hedef ERC20 ondalığı (PAXG = 18); dijeste ölçeklenmiş tutar girer.
    /// 🚨 Düğümün `unlock_token_decimals`ıyla AYNI olmalı, yoksa hiçbir fiş kabul edilmez.
    #[serde(default = "default_unlock_token_decimals")]
    pub unlock_token_decimals: u32,
    /// `eth_getLogs` taramaları arası bekleme. 🚨 Zagros taramasından ayrı:
    /// ortak olsaydı yerel taramayı hızlandıran, hız sınırlı Ethereum sağlayıcısına
    /// da yüklenirdi. Gecikmeye zaten `confirmation_depth` hakim.
    #[serde(default = "default_eth_poll_interval_secs")]
    pub poll_interval_secs: u64,

    /// Ethereum zincir kimliği (mainnet = 1). EIP-712 domain'ine girer; Zagros'un
    /// kendi `[bridge].chain_id`'sinden AYRIDIR ve karıştırılmamalıdır.
    #[serde(default = "default_ethereum_chain_id")]
    pub ethereum_chain_id: u64,

    /// Gateway `isRelayer` kümesindeki tüm relayer adresleri, sabit sırayla.
    /// Bu relayer'ın kendi adresi listede olmalı (fail-closed).
    pub relayer_addresses: Vec<String>,

    /// `true`: kalıcı `inbound_cursor` yok sayılır, `start_block`tan başlar.
    /// Tek seferlik kurtarma anahtarı; sonra `false`a döndürülmeli.
    #[serde(default)]
    pub reset_inbound_cursor: bool,
}

fn default_data_dir() -> String {
    "./zagros-relayer-data".to_string()
}

fn default_eth_poll_interval_secs() -> u64 {
    15
}

fn default_unlock_token_decimals() -> u32 {
    18 // PAXG
}

fn default_ethereum_chain_id() -> u64 {
    1 // Ethereum mainnet
}

fn default_max_log_range() -> u64 {
    10 // Alchemy ucretsiz plan siniri - en kisitlayici saglayiciya gore guvenli varsayilan
}

fn default_confirmation_depth() -> u64 {
    12
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZagrosEndpointConfig {
    /// Zagros düğümünün JSON-RPC HTTP uç noktası (örn. "http://127.0.0.1:8545").
    pub rpc_url: String,
    /// Yerel düğüm taramaları arası bekleme (ucuz, düşük tutulabilir).
    /// Kullanıcının hissettiği köprü gecikmesinin büyük kısmı buradan gelir.
    #[serde(default = "default_poll_interval_secs")]
    pub poll_interval_secs: u64,
}

fn default_poll_interval_secs() -> u64 {
    3
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeParamsConfig {
    /// `BridgeManager::propose_request_message`'ın imza mesajına dahil
    /// ettiği chain_id ile eşleşmeli (bkz. zagros_types::CHAIN_ID).
    pub chain_id: u64,
    /// Mint önerilerinde `source_chain` alanına yazılan sabit değer (örn.
    /// "Ethereum").
    #[serde(default = "default_source_chain_name")]
    pub source_chain_name: String,

    /// 🛡️ Güvenilen köprü yetkililerinin Ed25519 açık anahtarları (hex).
    /// İmzalar yalnız bu kümeye karşı doğrulanır. Zorunlu (serde default YOK):
    /// yapılandırılmazsa relayer başlamaz, dev seed'e sessizce düşmez.
    pub authorities: Vec<String>,

    /// M-of-N eşiği. Node'un `BridgeManager` eşiğiyle eşleşmeli.
    pub required_signatures: usize,

    /// ⏳ Zaman kilidi. 🚨 Düğümün `timelock_secs`iyle AYNI olmalı: relayer
    /// fiş zamanını kendi hesaplar; ayrışırsa erken fiş ya da hiç fiş. Üretimde 86400.
    #[serde(default = "default_bridge_timelock_secs")]
    pub timelock_secs: u64,

    /// `CursorGapError`da otomatik kurtarma; varsayılan `false` (fail-closed).
    /// `true`: imleç `oldest_available_index`e ilerler, aralık bu relayer için
    /// kalıcı atlanır; yalnız yedekli relayer dağıtımlarında güvenli.
    #[serde(default)]
    pub auto_recover_cursor_gap: bool,
}

fn default_bridge_timelock_secs() -> u64 {
    24 * 60 * 60
}

fn default_source_chain_name() -> String {
    "Ethereum".to_string()
}

#[derive(Debug)]
pub enum ConfigError {
    Io(String),
    Parse(String),
    Validation(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(msg) => write!(f, "IO error: {}", msg),
            ConfigError::Parse(msg) => write!(f, "Parse error: {}", msg),
            ConfigError::Validation(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

impl std::error::Error for ConfigError {}

/// `${VAR}` yer tutucularını ortam değişkenleriyle değiştirir. 🔐 API anahtarlı
/// uç noktalar düz metin durmasın. Tanımsız değişken FAIL-CLOSED: boş dizeyle
/// başlasa relayer hiçbir olay göremez, kullanıcı parasını kilitler, kimse hata görmezdi.
fn expand_env_placeholders(content: &str) -> Result<String, ConfigError> {
    let mut out = String::with_capacity(content.len());
    let mut rest = content;

    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            return Err(ConfigError::Parse(
                "unterminated ${...} placeholder in relayer config".to_string(),
            ));
        };
        let name = &after[..end];
        let value = std::env::var(name).map_err(|_| {
            ConfigError::Validation(format!(
                "environment variable {} referenced by the relayer config is not set",
                name
            ))
        })?;
        if value.trim().is_empty() {
            return Err(ConfigError::Validation(format!(
                "environment variable {} is set but empty",
                name
            )));
        }
        out.push_str(&value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

impl RelayerConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path).map_err(|e| ConfigError::Io(e.to_string()))?;
        let content = expand_env_placeholders(&content)?;
        let config: RelayerConfig =
            toml::from_str(&content).map_err(|e| ConfigError::Parse(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// Testler için `relayer.toml` yazar; üretimde kullanılmaz.
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), ConfigError> {
        let content =
            toml::to_string_pretty(self).map_err(|e| ConfigError::Parse(e.to_string()))?;
        fs::write(path, content).map_err(|e| ConfigError::Io(e.to_string()))
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.zagros_secret_key().map_err(|e| {
            ConfigError::Validation(format!("identity.zagros_signing_key_hex: {}", e))
        })?;
        self.ethereum_secret_key().map_err(|e| {
            ConfigError::Validation(format!("identity.ethereum_signing_key_hex: {}", e))
        })?;

        if self.ethereum.ws_rpc_url.is_empty() {
            return Err(ConfigError::Validation(
                "ethereum.ws_rpc_url must not be empty".to_string(),
            ));
        }
        if self.zagros.rpc_url.is_empty() {
            return Err(ConfigError::Validation(
                "zagros.rpc_url must not be empty".to_string(),
            ));
        }
        if !zagros_types::Transaction::validate_address(&self.ethereum.gateway_contract_address) {
            return Err(ConfigError::Validation(
                "ethereum.gateway_contract_address must be a 0x-prefixed 20-byte address"
                    .to_string(),
            ));
        }
        // 🛡️ ABI uyumsuzluğu fail-closed: yeni `TokensLocked` ABI'si (minAmountOut)
        // eski Gateway'den farklı topic0 üretir, filtre hiç eşleşmez ve yatırmalar
        // sessizce görülmezdi. Bilinen eski ABI adresine karşı başlamak reddedilir.
        const KNOWN_OLD_ABI_GATEWAY_ADDRESS: &str = "0xbeda78b7526e2c1cad82c94fe91fcbf9612e521f";
        if self
            .ethereum
            .gateway_contract_address
            .eq_ignore_ascii_case(KNOWN_OLD_ABI_GATEWAY_ADDRESS)
        {
            return Err(ConfigError::Validation(format!(
                "ethereum.gateway_contract_address ({}) bilinen ESKİ-ABI (minAmountOut'suz) \
                 Gateway kontratına işaret ediyor - relayer'ın beklediği YENİ ABI ile eşleşmiyor, \
                 bu adrese karşı başlatılırsa hiçbir TokensLocked olayı görülmez. \
                 Yeni Gateway kontratını deploy edip bu adresi güncelleyin.",
                self.ethereum.gateway_contract_address
            )));
        }
        if !zagros_types::Transaction::validate_address(&self.ethereum.unlock_token_address) {
            return Err(ConfigError::Validation(
                "ethereum.unlock_token_address must be a 0x-prefixed 20-byte address".to_string(),
            ));
        }

        // 🛡️ [8]: Güvenilir köprü yetkili kümesi fail-closed doğrulanır, böylece
        // eksik/bozuk `[bridge] authorities`/`required_signatures` ile relayer HİÇ
        // başlamaz (dev seed'e sessizce düşmek yerine).
        self.trusted_bridge_manager()
            .map_err(|e| ConfigError::Validation(format!("bridge authority set: {}", e)))?;

        // 🌉 FAZ4: Atanmış-sunucu relayer adres kümesi de fail-closed doğrulanır.
        self.relayer_eth_addresses()
            .map_err(|e| ConfigError::Validation(format!("relayer address set: {}", e)))?;

        Ok(())
    }

    /// 🛡️ Config'ten güvenilen `BridgeManager` (küme + eşik); outbound imza
    /// doğrulaması bunu kullanır. Geçersiz alan `Err` (fail-closed), panic yolu yok.
    pub fn trusted_bridge_manager(&self) -> Result<BridgeManager, String> {
        use ed25519_dalek::{VerifyingKey, PUBLIC_KEY_LENGTH};
        use std::collections::HashSet;
        use zagros_executor::bridge::BridgeAuthority;

        if self.bridge.authorities.is_empty() {
            return Err(
                "bridge.authorities must not be empty (fail-closed: refusing to fall back to dev seeds)"
                    .to_string(),
            );
        }

        let mut authorities = Vec::with_capacity(self.bridge.authorities.len());
        let mut seen = HashSet::new();
        for (i, hex_pk) in self.bridge.authorities.iter().enumerate() {
            let stripped = hex_pk.strip_prefix("0x").unwrap_or(hex_pk);
            let raw = hex::decode(stripped)
                .map_err(|e| format!("authorities[{}] invalid hex: {}", i, e))?;
            let pk: [u8; PUBLIC_KEY_LENGTH] = raw.as_slice().try_into().map_err(|_| {
                format!(
                    "authorities[{}] must be {} bytes, got {}",
                    i,
                    PUBLIC_KEY_LENGTH,
                    raw.len()
                )
            })?;
            // Geçersiz Ed25519 noktalarını reddet (fail-closed).
            VerifyingKey::from_bytes(&pk)
                .map_err(|e| format!("authorities[{}] invalid ed25519 key: {}", i, e))?;
            let address = BridgeManager::derive_address_from_public_key(&pk);
            if !seen.insert(address.clone()) {
                return Err(format!("authorities[{}] duplicate authority (same key)", i));
            }
            authorities.push(BridgeAuthority {
                address,
                public_key: pk,
                is_active: true,
            });
        }

        let req = self.bridge.required_signatures;
        if req < 2 {
            return Err(format!("required_signatures must be >= 2, got {}", req));
        }
        if req > authorities.len() {
            return Err(format!(
                "required_signatures ({}) exceeds authority count ({})",
                req,
                authorities.len()
            ));
        }

        // 🚨 Zaman kilidini de bağla: relayer `executable_at`'i KENDİ güvendiği
        // manager'ın kilidiyle hesaplar. Bağlanmazsa varsayılan 24 saat kalır ve
        // düğüm kısa bir kilit kullanıyorsa relayer fişleri asla üretmez.
        Ok(BridgeManager::new(authorities, req, self.bridge.chain_id)
            .with_timelock_secs(self.bridge.timelock_secs))
    }

    /// `relayer_addresses`i doğrulanmış listeye çevirir; boş, geçersiz ya da kendi
    /// adresi yoksa `Err` (fail-closed).
    pub fn relayer_eth_addresses(&self) -> Result<Vec<ethers_core::types::Address>, String> {
        use std::str::FromStr;
        if self.ethereum.relayer_addresses.is_empty() {
            return Err("ethereum.relayer_addresses must not be empty".to_string());
        }
        let mut out = Vec::with_capacity(self.ethereum.relayer_addresses.len());
        for (i, a) in self.ethereum.relayer_addresses.iter().enumerate() {
            let addr = ethers_core::types::Address::from_str(a)
                .map_err(|e| format!("ethereum.relayer_addresses[{}] invalid: {}", i, e))?;
            out.push(addr);
        }
        let mine = ethers_core::types::Address::from_str(&self.ethereum_address()?)
            .map_err(|e| format!("own ethereum address invalid: {}", e))?;
        if !out.contains(&mine) {
            return Err(
                "ethereum.relayer_addresses must include this relayer's own ethereum address"
                    .to_string(),
            );
        }
        Ok(out)
    }

    /// Ed25519 kimlik anahtarını hex'ten çözer.
    pub fn zagros_secret_key(&self) -> Result<SigningKey, String> {
        let bytes = decode_hex_32(&self.identity.zagros_signing_key_hex)?;
        Ok(SigningKey::from_bytes(&bytes))
    }

    /// Bu relayer'ın Zagros köprü yetkilisi olarak kayıtlı olması gereken
    /// adresi türetir, `BridgeManager::default_authorities()`'in de
    /// kullandığı aynı türetme (keccak256(pubkey) -> son 20 bayt).
    pub fn zagros_authority_address(&self) -> Result<String, String> {
        let signing_key = self.zagros_secret_key()?;
        Ok(BridgeManager::derive_address_from_public_key(
            &signing_key.verifying_key().to_bytes(),
        ))
    }

    /// secp256k1 kimlik anahtarını hex'ten çözer.
    pub fn ethereum_secret_key(&self) -> Result<SecretKey, String> {
        let bytes = decode_hex_32(&self.identity.ethereum_signing_key_hex)?;
        SecretKey::from_slice(bytes.as_slice()).map_err(|e| e.to_string())
    }

    /// Bu relayer'ın Ethereum tarafında (ZagrosBridgeGateway.sol'un
    /// `isRelayer` listesinde) kayıtlı olması gereken adresi türetir, aynı
    /// keccak256(pubkey) türetmesi, zaten Ethereum-uyumlu.
    pub fn ethereum_address(&self) -> Result<String, String> {
        let secret_key = self.ethereum_secret_key()?;
        Ok(Transaction::address_from_secret_key(&secret_key))
    }
}

/// Ham baytları `Zeroizing<[u8;32]>` içinde döner, ara `Vec` sıfırlanır.
fn decode_hex_32(hex_str: &str) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes =
        zeroize::Zeroizing::new(hex::decode(stripped).map_err(|e| format!("invalid hex: {}", e))?);
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut array = zeroize::Zeroizing::new([0u8; 32]);
    array.copy_from_slice(&bytes);
    Ok(array)
}

/// Crate genelinde (`cursor_recover_cmd.rs` gibi diğer modüllerin testleri
/// dahil) `validate()`'i geçen bir örnek config üretir, yalnızca testler
/// için, `#[cfg(test)]` altında derlenir.
#[cfg(test)]
pub(crate) fn sample_config_for_tests() -> RelayerConfig {
    let mut config = RelayerConfig {
        data_dir: default_data_dir(),
        identity: IdentityConfig {
            zagros_signing_key_hex: "11".repeat(32),
            ethereum_signing_key_hex: "22".repeat(32),
        },
        ethereum: EthereumConfig {
            ws_rpc_url: "wss://eth.example.com".to_string(),
            gateway_contract_address: "0x1111111111111111111111111111111111111111".to_string(),
            confirmation_depth: 12,
            start_block: 0,
            max_log_range: 10,
            unlock_token_decimals: 6,
            poll_interval_secs: 15,
            ethereum_chain_id: 1,
            unlock_token_address: "0x2222222222222222222222222222222222222222".to_string(),
            // 🌉 FAZ4: kendi eth adresimiz aşağıda eklenir (fail-closed kural).
            relayer_addresses: Vec::new(),
            reset_inbound_cursor: false,
        },
        zagros: ZagrosEndpointConfig {
            rpc_url: "http://127.0.0.1:8545".to_string(),
            poll_interval_secs: 15,
        },
        bridge: BridgeParamsConfig {
            chain_id: 21072026,
            source_chain_name: "Ethereum".to_string(),
            // Geçerli 2-of-3 küme: kanonik default yetkililerin public key'leri.
            authorities: BridgeManager::default_authorities()
                .iter()
                .map(|a| hex::encode(a.public_key))
                .collect(),
            required_signatures: 2,
            timelock_secs: default_bridge_timelock_secs(),
            auto_recover_cursor_gap: false,
        },
        idempotency: IdempotencyConfig::default(),
    };
    // Kendi eth adresimizi relayer kümesine ekle (validate() bunu ZORUNLU kılar).
    let mine = config.ethereum_address().unwrap();
    config.ethereum.relayer_addresses = vec![
        mine,
        "0x3333333333333333333333333333333333333333".to_string(),
    ];
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> RelayerConfig {
        sample_config_for_tests()
    }

    /// item 14: `IdentityConfig`'in manuel `Debug` impl'i İKİ özel anahtarı da
    /// REDAKTE etmeli, bir `{:?}` çağrısı (ya da onu içeren bir panik mesajı)
    /// düz metin Ed25519/secp256k1 anahtarı SIZDIRMAMALI.
    #[test]
    fn identity_config_debug_output_redacts_both_secret_keys() {
        let identity = IdentityConfig {
            zagros_signing_key_hex: "11".repeat(32),
            ethereum_signing_key_hex: "22".repeat(32),
        };
        let debug_output = format!("{:?}", identity);
        assert!(
            !debug_output.contains(&"11".repeat(32)),
            "Debug çıktısı Zagros özel anahtarını SIZDIRMAMALI: {}",
            debug_output
        );
        assert!(
            !debug_output.contains(&"22".repeat(32)),
            "Debug çıktısı Ethereum özel anahtarını SIZDIRMAMALI: {}",
            debug_output
        );
        assert_eq!(
            debug_output.matches("<redacted>").count(),
            2,
            "her iki alan da redakte edilmeli: {}",
            debug_output
        );
    }

    /// `Zeroizing<[u8;32]>` geçerli `SecretKey`/`SigningKey` türetebilmeli.
    #[test]
    fn secret_key_from_zeroizing_hex_round_trips_a_valid_key() {
        let config = RelayerConfig {
            identity: IdentityConfig {
                zagros_signing_key_hex: "11".repeat(32),
                ethereum_signing_key_hex: "22".repeat(32),
            },
            ..sample_config()
        };

        let zagros_key = config
            .zagros_secret_key()
            .expect("gecerli Ed25519 anahtari");
        let ethereum_key = config
            .ethereum_secret_key()
            .expect("gecerli secp256k1 anahtari");

        // Aynı hex'ten türetilen adresler her çağrıda AYNI olmalı (determinizm
        // korunmuş, Zeroizing sarmalayıcısı baytları BOZMAMIŞ).
        assert_eq!(
            zagros_key.verifying_key().to_bytes(),
            config
                .zagros_secret_key()
                .unwrap()
                .verifying_key()
                .to_bytes()
        );
        assert_eq!(
            ethereum_key.secret_bytes(),
            config.ethereum_secret_key().unwrap().secret_bytes()
        );
    }

    #[test]
    fn valid_config_passes_validation() {
        assert!(sample_config().validate().is_ok());
    }

    #[test]
    fn derives_distinct_addresses_for_the_two_keys() {
        let config = sample_config();
        let zagros_address = config.zagros_authority_address().unwrap();
        let ethereum_address = config.ethereum_address().unwrap();

        assert!(zagros_address.starts_with("0x"));
        assert!(ethereum_address.starts_with("0x"));
        // Farklı şemalar/anahtarlar farklı adresler türetmeli, aynı anahtarın
        // iki zincirde yeniden kullanılmadığının somut kanıtı.
        assert_ne!(zagros_address, ethereum_address);
    }

    #[test]
    fn rejects_malformed_zagros_key_hex() {
        let mut config = sample_config();
        config.identity.zagros_signing_key_hex = "not-hex".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_wrong_length_ethereum_key_hex() {
        let mut config = sample_config();
        config.identity.ethereum_signing_key_hex = "aa".repeat(16); // 16 bayt, 32 değil
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_empty_rpc_urls() {
        let mut config = sample_config();
        config.zagros.rpc_url = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_malformed_gateway_address() {
        let mut config = sample_config();
        config.ethereum.gateway_contract_address = "not-an-address".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_round_trips_through_toml() {
        let config = sample_config();
        let toml_str = toml::to_string(&config).unwrap();
        let parsed: RelayerConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(
            config.identity.zagros_signing_key_hex,
            parsed.identity.zagros_signing_key_hex
        );
        assert_eq!(config.ethereum.ws_rpc_url, parsed.ethereum.ws_rpc_url);
    }

    // ---- [8]: Güvenilir köprü yetkili kümesi (config-driven) ----

    #[test]
    fn trusted_bridge_manager_builds_the_configured_set() {
        let config = sample_config();
        let mgr = config
            .trusted_bridge_manager()
            .expect("valid authority set");
        assert_eq!(mgr.required_signatures(), 2);
        // Kümenin gerçekten config'teki (default) yetkililerle eşleştiğini,
        // onların imzalarını doğrulayabildiğini kanıtla (dev seed'le AYNI olmasa
        // bile mantık config'ten gelir).
        assert_eq!(mgr.chain_id(), config.bridge.chain_id);
    }

    #[test]
    fn validate_rejects_empty_authority_set_fail_closed() {
        // 🛡️ [8]: Boş authorities → relayer BAŞLAMAMALI (dev seed'e düşmek yerine).
        let mut config = sample_config();
        config.bridge.authorities.clear();
        assert!(config.validate().is_err());
        assert!(config.trusted_bridge_manager().is_err());
    }

    #[test]
    fn validate_rejects_threshold_above_authority_count() {
        let mut config = sample_config();
        config.bridge.required_signatures = 4; // 3 yetkili var
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_threshold_below_two() {
        let mut config = sample_config();
        config.bridge.required_signatures = 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_malformed_authority_key() {
        let mut config = sample_config();
        config.bridge.authorities[0] = "zz-not-hex".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_duplicate_authorities() {
        let mut config = sample_config();
        config.bridge.authorities[1] = config.bridge.authorities[0].clone();
        assert!(config.validate().is_err());
    }

    // ---- 🌉 FAZ4: relayer Ethereum adres kümesi ----

    #[test]
    fn relayer_eth_addresses_parses_and_includes_own_address() {
        let config = sample_config();
        let addrs = config.relayer_eth_addresses().expect("valid set");
        let mine: ethers_core::types::Address = config.ethereum_address().unwrap().parse().unwrap();
        assert!(addrs.contains(&mine));
    }

    #[test]
    fn validate_rejects_empty_relayer_address_set() {
        let mut config = sample_config();
        config.ethereum.relayer_addresses.clear();
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_set_without_own_address() {
        // 🌉 FAZ4 fail-closed: kendi adresimiz kümede yoksa unlock sunamayız → reddet.
        let mut config = sample_config();
        config.ethereum.relayer_addresses = vec![
            "0x4444444444444444444444444444444444444444".to_string(),
            "0x5555555555555555555555555555555555555555".to_string(),
        ];
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_malformed_relayer_address() {
        let mut config = sample_config();
        config
            .ethereum
            .relayer_addresses
            .push("not-an-eth-address".to_string());
        assert!(config.validate().is_err());
    }

    /// Eski `relayer.toml`da `auto_recover_cursor_gap` yoksa `false` parse edilmeli.
    #[test]
    fn auto_recover_cursor_gap_defaults_to_false_when_toml_omits_it() {
        let toml_str = r#"
            chain_id = 21072026
            authorities = []
            required_signatures = 2
        "#;
        let parsed: BridgeParamsConfig = toml::from_str(toml_str).unwrap();
        assert!(!parsed.auto_recover_cursor_gap);
    }

    // 🔐 ${VAR} GENİŞLETME TESTLERİ

    #[test]
    fn expands_a_placeholder_from_the_environment() {
        // SAFETY: test-only; bu degisken adi baska hicbir testte kullanilmiyor.
        unsafe { std::env::set_var("ZAGROS_TEST_WS_URL_OK", "wss://ornek.example/abc") };
        let out = expand_env_placeholders("ws_rpc_url = \"${ZAGROS_TEST_WS_URL_OK}\"").unwrap();
        assert_eq!(out, "ws_rpc_url = \"wss://ornek.example/abc\"");
    }

    /// 🚨 FAIL-CLOSED: tanimsiz degisken bos dizeye DUSMEMELI.
    /// Duseydi relayer sorunsuz baslar ama hicbir TokensLocked olayini goremezdi;
    /// kullanici parasini kilitler, karsiligi hic gelmez ve kimse hata gormezdi.
    #[test]
    fn an_undefined_variable_is_an_error_not_an_empty_string() {
        let error =
            expand_env_placeholders("x = \"${ZAGROS_TEST_DEFINITELY_UNSET_VAR}\"").unwrap_err();
        assert!(format!("{}", error).contains("is not set"));
    }

    /// Tanimli ama BOS bir degisken de reddedilmeli, ayni sessiz-basarisizlik riski.
    #[test]
    fn an_empty_variable_is_rejected() {
        unsafe { std::env::set_var("ZAGROS_TEST_WS_URL_EMPTY", "   ") };
        let error = expand_env_placeholders("x = \"${ZAGROS_TEST_WS_URL_EMPTY}\"").unwrap_err();
        assert!(format!("{}", error).contains("empty"));
    }

    #[test]
    fn content_without_placeholders_passes_through_unchanged() {
        let raw = "ws_rpc_url = \"wss://ethereum-rpc.publicnode.com\"\nchain_id = 1\n";
        assert_eq!(expand_env_placeholders(raw).unwrap(), raw);
    }

    #[test]
    fn an_unterminated_placeholder_is_rejected() {
        assert!(expand_env_placeholders("x = \"${OPEN").is_err());
    }
}
